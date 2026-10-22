//! Membership security specification (design.md, Membership / Removing a device).
//!
//! `past(e)` is entry e's strict causal past. A device's admissions are the
//! genesis `Create` (its creator's) and every `Add` of it. Seniority ranks a
//! device by its first admission: the lowest (DAG depth, entry hash) among its
//! admissions that are authorized when no removal applies. An `Add` must see an
//! admission of its author, so a newly invited device always sits deeper than
//! its inviter.
//!
//! Authority under a set S of removals: the genesis is authorized. Any other
//! membership operation e is authorized iff no removal in S of e's author (other
//! than e itself) misses e, and past(e) holds an authorized admission of e's
//! author. So a removal cuts every operation by its target that it did not see,
//! including authority delegated through an arbitrary chain of `Add`s, while
//! additions it saw survive the inviter's removal. Any surviving admission will
//! do: an extra `Add` never takes authority away.
//!
//! S is valid iff each removal R in S is authorized, past(R) holds an
//! authorized admission of R's target, and past(R) holds no other removal in S
//! of that target. The winning removals are the lexicographically greatest valid
//! S with removals ordered by (author seniority, removal depth, removal hash).
//! Members are the devices with an authorized admission, minus the winners'
//! targets: removed keys never rejoin. A removed device's data counts up to the
//! highest cutoff among the winners that removed it. The name is the highest
//! hash among authorized names that no authorized rename saw.
//!
//! Judgment call: generalize mutual-removal seniority to ALL conflicting
//! removals, including longer cycles. A junior cannot undo a senior's removal by
//! removing its author or cutting an admission that authorized it. Unrelated
//! removals coexist.
//!
//! Acceptance is causal, never arrival-dependent. An entry is rejected unless
//! its author is a member of its causal past, and a removal also unless its
//! target is. Join consent covers the vault, the inviter (the `Add`'s author)
//! and the new device, so it cannot back another device's `Add`. An attacker can
//! hide knowledge using old parents: that is indistinguishable from an offline
//! write and may be stored, but its effects beyond the removal's cutoff are
//! ignored. Delivery order must not affect membership, names, or visible data.
//!
//! Known limitations (design.md, Membership):
//! - A causal removal is final only if the remover is senior to its target. A
//!   removed device senior to its remover can sign a removal of the remover with
//!   parents from before its own removal, and seniority wins it the race
//!   (`known_limitation_removed_senior_returns_with_hidden_parents`).
//! - Seniority ignores cuts. A device whose first `Add` was cut but which holds
//!   another surviving `Add` keeps the first one's rank. A removed device that
//!   had written a hidden `Add` of a device that another member later adds thus
//!   lends it its early rank. Consent commits to neither seq nor parents, so one
//!   inviter can also do it alone with a single consent: if its own first
//!   admission was cut and it was admitted again, it can write an early, cut
//!   `Add` and a later, surviving one. Either way this only changes who wins
//!   removal races
//!   (`known_limitation_cut_first_add_keeps_seniority`).

use crate::*;
use proptest::prelude::*;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

// Independent reference model: a direct, brute-force reading of the
// specification above. It shares no code with `membership.rs` or `Vault`:
// explicit transitive closure of hashes (no Node, Clock or `saw`), authority by
// recursion back to the genesis, seniority from that recursion, and an
// exhaustive search over every subset of every removal. Deliberately
// exponential and suitable only for small test histories.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Model {
    members: BTreeSet<DeviceId>,
    cutoffs: BTreeMap<DeviceId, Option<u64>>,
    name: String,
}

struct Graph<'a> {
    entries: Vec<&'a Entry>,
    past: Vec<BTreeSet<usize>>,
    depth: Vec<usize>,
    genesis: Option<usize>,
}

impl<'a> Graph<'a> {
    fn new(entries: &'a [Entry]) -> Self {
        let mut graph = Self {
            entries: Vec::new(),
            past: Vec::new(),
            depth: Vec::new(),
            genesis: None,
        };
        // Inputs may be delivered in any order. Build the DAG by actual hashes.
        while graph.entries.len() < entries.len() {
            let entry = entries
                .iter()
                .find(|entry| {
                    !graph.entries.iter().any(|e| e.hash() == entry.hash())
                        && entry
                            .deps()
                            .iter()
                            .all(|hash| graph.entries.iter().any(|e| e.hash() == *hash))
                })
                .expect("complete acyclic history");
            let parents: Vec<_> = entry
                .deps()
                .iter()
                .map(|hash| {
                    graph
                        .entries
                        .iter()
                        .position(|e| e.hash() == *hash)
                        .unwrap()
                })
                .collect();
            let mut past = BTreeSet::new();
            for &p in &parents {
                past.insert(p);
                past.extend(&graph.past[p]);
            }
            let depth = parents
                .iter()
                .map(|&p| graph.depth[p] + 1)
                .max()
                .unwrap_or(0);
            graph.entries.push(entry);
            graph.past.push(past);
            graph.depth.push(depth);
        }
        graph.genesis = (0..graph.entries.len())
            .filter(|&i| {
                let e = graph.entries[i];
                matches!(
                    e.payload(),
                    Payload::Membership(MembershipOp::Create { device, nonce, .. })
                        if *device == e.author()
                            && e.deps().is_empty()
                            && VaultId::derive(device, nonce) == e.vault()
                )
            })
            .min_by_key(|&i| (graph.depth[i], graph.entries[i].hash()));
        graph
    }

    fn membership(&self, i: usize) -> Option<&MembershipOp> {
        match self.entries[i].payload() {
            Payload::Membership(op) => Some(op),
            Payload::Data(_) => None,
        }
    }

    fn removals(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.entries.len())
            .filter(|&i| matches!(self.membership(i), Some(MembershipOp::Remove { .. })))
    }

    fn target(&self, r: usize) -> DeviceId {
        match self.membership(r) {
            Some(MembershipOp::Remove { device, .. }) => *device,
            _ => panic!("not a removal"),
        }
    }

    fn admissions(&self, device: DeviceId) -> impl Iterator<Item = usize> + '_ {
        (0..self.entries.len()).filter(move |&i| match self.membership(i) {
            Some(MembershipOp::Add { device: added, .. }) => *added == device,
            Some(MembershipOp::Create {
                device: creator, ..
            }) => self.genesis == Some(i) && *creator == device,
            _ => false,
        })
    }

    fn authorized(&self, i: usize, removals: &[usize]) -> bool {
        if self.genesis == Some(i) {
            return true;
        }
        match self.membership(i) {
            None | Some(MembershipOp::Create { .. }) => return false,
            Some(_) => {}
        }
        let author = self.entries[i].author();
        if removals
            .iter()
            .any(|&r| r != i && self.target(r) == author && !self.past[r].contains(&i))
        {
            return false;
        }
        self.admitted(author, i, removals)
    }

    // Whether past(i) holds an authorized admission of `device`.
    fn admitted(&self, device: DeviceId, i: usize, removals: &[usize]) -> bool {
        self.admissions(device)
            .any(|a| self.past[i].contains(&a) && self.authorized(a, removals))
    }

    fn seniority(&self, device: DeviceId) -> Option<(usize, Hash)> {
        self.admissions(device)
            .filter(|&a| self.authorized(a, &[]))
            .map(|a| (self.depth[a], self.entries[a].hash()))
            .min()
    }

    fn valid(&self, removals: &[usize]) -> bool {
        removals.iter().all(|&r| {
            self.authorized(r, removals)
                && self.admitted(self.target(r), r, removals)
                && !removals.iter().any(|&other| {
                    other != r
                        && self.target(other) == self.target(r)
                        && self.past[r].contains(&other)
                })
        })
    }

    fn model(&self) -> Model {
        let mut order: Vec<_> = self.removals().collect();
        order.sort_by_key(|&r| {
            let rank = self.seniority(self.entries[r].author());
            (rank.is_none(), rank, self.depth[r], self.entries[r].hash())
        });
        assert!(order.len() <= 12, "the model is exponential");
        // Descending masks with the most senior removal as the top bit visit
        // subsets in decreasing lexicographic order.
        let winners = (0..1usize << order.len())
            .rev()
            .map(|mask| {
                order
                    .iter()
                    .enumerate()
                    .filter(|(bit, _)| mask & (1 << (order.len() - 1 - bit)) != 0)
                    .map(|(_, &r)| r)
                    .collect::<Vec<_>>()
            })
            .find(|set| self.valid(set))
            .expect("the empty set is valid");
        let mut members: BTreeSet<DeviceId> = (0..self.entries.len())
            .filter(|&i| self.authorized(i, &winners))
            .filter_map(|i| match self.membership(i) {
                Some(MembershipOp::Create { device, .. } | MembershipOp::Add { device, .. }) => {
                    Some(*device)
                }
                _ => None,
            })
            .collect();
        let mut cutoffs: BTreeMap<DeviceId, Option<u64>> = BTreeMap::new();
        for &r in &winners {
            if let Some(MembershipOp::Remove {
                device,
                last_seen_seq,
            }) = self.membership(r)
            {
                members.remove(device);
                let cutoff = cutoffs.entry(*device).or_default();
                *cutoff = (*cutoff).max(*last_seen_seq);
            }
        }
        let names: Vec<_> = (0..self.entries.len())
            .filter(|&i| {
                matches!(
                    self.membership(i),
                    Some(MembershipOp::Create { .. } | MembershipOp::Rename { .. })
                ) && self.authorized(i, &winners)
            })
            .collect();
        let name = names
            .iter()
            .copied()
            .filter(|&i| !names.iter().any(|&j| self.past[j].contains(&i)))
            .max_by_key(|&i| self.entries[i].hash())
            .and_then(|i| match self.membership(i) {
                Some(MembershipOp::Create { name, .. } | MembershipOp::Rename { name }) => {
                    Some(name.clone())
                }
                _ => None,
            })
            .unwrap_or_default();
        Model {
            members,
            cutoffs,
            name,
        }
    }

    // The entry indices in the causal past of `deps`, inclusive.
    fn closure(&self, deps: impl IntoIterator<Item = Hash>) -> BTreeSet<usize> {
        deps.into_iter()
            .flat_map(|hash| {
                let i = self.entries.iter().position(|e| e.hash() == hash).unwrap();
                self.past[i].iter().copied().chain(std::iter::once(i))
            })
            .collect()
    }

    // The model's verdict on applying `entry` after `self`'s entries.
    fn accepts(&self, entry: &Entry) -> Result<bool, Error> {
        let past: Vec<_> = self
            .closure(entry.deps().iter().copied())
            .into_iter()
            .map(|i| self.entries[i].clone())
            .collect();
        let state = model(&past);
        if !state.members.contains(&entry.author()) {
            return Err(Error::NotMember);
        }
        match entry.payload() {
            Payload::Membership(MembershipOp::Remove { device, .. })
                if !state.members.contains(device) =>
            {
                Err(Error::RemoveNonMember)
            }
            _ => Ok(true),
        }
    }
}

fn model(entries: &[Entry]) -> Model {
    Graph::new(entries).model()
}

fn key(n: u8) -> DeviceSecret {
    DeviceSecret::from_bytes(&[n; 32])
}

/// `device`'s consent to be added to `vault` by `inviter`.
fn consent(device: &DeviceSecret, vault: &Vault, inviter: &DeviceSecret) -> Signature {
    device.join_consent(&vault.id(), &inviter.device_id())
}

fn genesis(a: &DeviceSecret) -> Entry {
    let device = a.device_id();
    let nonce = [0; 32];
    Entry::sign(
        a,
        VaultId::derive(&device, &nonce),
        0,
        [],
        Payload::Membership(MembershipOp::Create {
            device,
            nonce,
            name: "test".into(),
        }),
    )
}

fn load(entries: &[Entry]) -> Vault {
    Vault::load(entries.iter().cloned()).unwrap()
}

fn all(vault: &Vault) -> Vec<Entry> {
    vault.entries().into_iter().cloned().collect()
}

fn assert_state(vault: &Vault, entries: &[Entry]) {
    assert_model(vault, entries, &model(entries));
}

fn assert_model(vault: &Vault, entries: &[Entry], expected: &Model) {
    assert_eq!(vault.members().collect::<BTreeSet<_>>(), expected.members);
    assert_eq!(vault.name(), expected.name);
    // Generated writes each create one valid login, so visibility is exactly
    // membership/cutoff authorization. This also checks retroactive rollback.
    let visible: BTreeSet<_> = entries
        .iter()
        .filter(|e| e.log() == Log::Data)
        .filter(|e| {
            expected.members.contains(&e.author())
                || expected
                    .cutoffs
                    .get(&e.author())
                    .is_some_and(|c| c.is_some_and(|seq| e.seq() <= seq))
        })
        .map(|e| ItemId::of_create(&e.hash(), 0))
        .collect();
    assert_eq!(
        vault.items().iter().map(|i| i.id).collect::<BTreeSet<_>>(),
        visible
    );
}

fn deliver(entries: &[Entry], seed: u64) {
    let mut pending: Vec<_> = entries[1..].iter().collect();
    // A reproducible shuffle independent of the DAG and admission ordering.
    let mut state = seed;
    for i in (1..pending.len()).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        pending.swap(i, (state as usize) % (i + 1));
    }
    let mut vault = load(&entries[..1]);
    while !pending.is_empty() {
        let before = pending.len();
        pending.retain(|e| match vault.apply((*e).clone()) {
            Ok(true) => false,
            Err(Error::MissingDeps(_) | Error::SeqGap { .. }) => true,
            result => panic!("unexpected delivery result: {result:?}"),
        });
        assert!(pending.len() < before);
    }
    assert_state(&vault, entries);
    // Reject entries that acknowledge removal, without changing stored heads.
    for device in (1..=5)
        .map(key)
        .filter(|key| !vault.is_member(&key.device_id()))
        .collect::<Vec<_>>()
    {
        for payload in [
            Payload::Membership(MembershipOp::Rename {
                name: "hostile".into(),
            }),
            data(),
        ] {
            let log = LogId {
                author: device.device_id(),
                log: payload.log(),
            };
            let seq = vault.heads().get(&log).map_or(0, |s| s + 1);
            let deps = entries
                .iter()
                .filter(|e| log.log == Log::Data || e.log() == Log::Membership)
                .map(Entry::hash);
            let entry = Entry::sign(&device, vault.id(), seq, deps, payload);
            let heads = vault.heads();
            let count = vault.entries().len();
            assert_eq!(vault.apply(entry), Err(Error::NotMember));
            assert_eq!(vault.heads(), heads);
            assert_eq!(vault.entries().len(), count);
        }
    }
}

fn data() -> Payload {
    Payload::Data(vec![DataOp::create(
        "login",
        None,
        [("password".into(), Field::new(FieldType::Secret, "test"))],
    )])
}

// Every attempted entry has a real signature. Parent choice deliberately forks
// old snapshots, but always includes the previous same-log entry. The model
// decides causal acceptance; the real API must agree. Adds may duplicate,
// re-add removed keys, or carry consent meant for another inviter.
fn history(devices: usize, steps: &[(u8, u8, u8, u16)]) -> Vec<Entry> {
    let keys: Vec<_> = (1..=devices as u8).map(key).collect();
    let mut vault = load(&[genesis(&keys[0])]);
    vault
        .add(
            &keys[0],
            keys[1].device_id(),
            consent(&keys[1], &vault, &keys[0]),
        )
        .unwrap();
    let mut entries = all(&vault);
    for &(author, target, kind, branch) in steps {
        let inviter = &keys[(author as usize + 1) % devices];
        let author = &keys[author as usize % devices];
        let target = &keys[target as usize % devices];
        let payload = match kind % 5 {
            0 => Payload::Membership(MembershipOp::Add {
                device: target.device_id(),
                consent: consent(target, &vault, author),
            }),
            1 => Payload::Membership(MembershipOp::Remove {
                device: target.device_id(),
                last_seen_seq: (branch % 3).checked_sub(1).map(u64::from),
            }),
            2 => Payload::Membership(MembershipOp::Rename {
                name: format!("name-{branch}"),
            }),
            3 => data(),
            _ => Payload::Membership(MembershipOp::Add {
                device: target.device_id(),
                consent: consent(target, &vault, inviter),
            }),
        };
        let forged = kind % 5 == 4;
        let log = LogId {
            author: author.device_id(),
            log: payload.log(),
        };
        let possible: Vec<_> = entries
            .iter()
            .filter(|e| log.log == Log::Data || e.log() == Log::Membership)
            .collect();
        let parent = possible[branch as usize % possible.len()];
        let previous = entries.iter().rev().find(|e| e.log_id() == log);
        let deps: BTreeSet<_> = std::iter::once(parent.hash())
            .chain(previous.map(Entry::hash))
            .collect();
        let entry = Entry::sign(
            author,
            vault.id(),
            previous.map_or(0, |e| e.seq() + 1),
            deps,
            payload,
        );
        let expected = if forged {
            Err(Error::InvalidConsent)
        } else {
            Graph::new(&entries).accepts(&entry)
        };
        assert_eq!(vault.apply(entry.clone()), expected);
        if expected.is_ok() {
            entries.push(entry);
        }
        assert_state(&vault, &entries);
    }
    entries
}

fn cases() -> u32 {
    std::env::var("DEADBOLT_MEMBERSHIP_CASES")
        .ok()
        .map(|n| n.parse().expect("case count"))
        .unwrap_or(16)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), ..ProptestConfig::default() })]

    #[test]
    fn signed_histories_converge_to_model(
        devices in 3usize..=5,
        steps in prop::collection::vec((any::<u8>(), any::<u8>(), any::<u8>(), any::<u16>()), 1..=10),
        seed in any::<u64>(),
    ) {
        let entries = history(devices, &steps);
        for order in [seed, seed.wrapping_add(1), !seed] { deliver(&entries, order); }
    }

    #[test]
    fn senior_survives_delegated_race(hops in 1usize..=3, delay in 0usize..=4, salt in any::<u64>()) {
        let keys: Vec<_> = (1..=5).map(key).collect();
        let mut honest = load(&[genesis(&keys[0])]);
        honest.add(&keys[0], keys[1].device_id(), consent(&keys[1], &honest, &keys[0])).unwrap();
        let mut thief = load(&all(&honest));
        for i in 0..delay { honest.rename(&keys[0], format!("name-{salt}-{i}")).unwrap(); }
        honest.remove(&keys[0], keys[1].device_id()).unwrap();
        for i in 1..=hops { thief.add(&keys[i], keys[i + 1].device_id(), consent(&keys[i + 1], &thief, &keys[i])).unwrap(); }
        thief.remove(&keys[hops + 1], keys[0].device_id()).unwrap();
        let mut entries = all(&honest);
        for entry in thief.entries() { if !entries.iter().any(|e| e.hash() == entry.hash()) { entries.push(entry.clone()); } }
        for order in [salt, !salt] { deliver(&entries, order); }
        assert_eq!(model(&entries).members, BTreeSet::from([keys[0].device_id()]));
    }
}

// Every DAG of up to DEADBOLT_MEMBERSHIP_DEPTH entries (default 3) over three
// keys, starting from the genesis and from the genesis plus A's Add of B:
// every parent antichain of membership entries, every author that is a member
// there, and every operation: Adds of any other key (duplicates and re-adds
// included), removals of any key with either cutoff (self, non-members and
// removed keys included), renames and data. Each DAG is built once, in one
// causal order, by applying its newest entry to a copy of its parent's vault,
// which must match the model. Entries the model rejects must be rejected; the
// resolver alone must still match the model with them included.
#[test]
fn exhaustive_small_histories() {
    struct Search {
        keys: Vec<DeviceSecret>,
        vault: VaultId,
        histories: usize,
        // Models of causal pasts by their hashes; pasts recur across siblings.
        models: RefCell<HashMap<Vec<Hash>, Model>>,
        consents: BTreeMap<(DeviceId, DeviceId), Signature>,
        // Entries before this index are the fixed start of the search.
        start: usize,
    }

    // A linear extension of causality: deps are always shallower. Appending
    // only in increasing order visits each DAG once instead of once per
    // interleaving of its concurrent entries.
    fn order(depth: usize, author: &DeviceId, deps: &[Hash], payload: &Payload) -> (usize, String) {
        (depth, format!("{author:?}{deps:?}{payload:?}"))
    }

    impl Search {
        fn model(&self, entries: &[Entry], past: &BTreeSet<usize>) -> Model {
            let key = past.iter().map(|&i| entries[i].hash()).collect();
            self.models
                .borrow_mut()
                .entry(key)
                .or_insert_with(|| {
                    model(&past.iter().map(|&i| entries[i].clone()).collect::<Vec<_>>())
                })
                .clone()
        }

        // Compare a vault holding `entries` with the model, or failing that the
        // resolver itself (histories the API rejects never reach a vault).
        fn check(&self, entries: &[Entry], vault: Option<&Vault>) {
            let graph = Graph::new(entries);
            let expected = graph.model();
            if let Some(vault) = vault {
                assert_model(vault, entries, &expected);
                return;
            }
            let nodes: Vec<_> = graph
                .entries
                .iter()
                .enumerate()
                .map(|(i, &entry)| {
                    let mut clock = BTreeMap::new();
                    for ancestor in graph.past[i].iter().copied().chain(std::iter::once(i)) {
                        let e = graph.entries[ancestor];
                        let seq = clock.entry(e.log_id()).or_insert(0);
                        *seq = (*seq).max(e.seq());
                    }
                    crate::vault::Node {
                        entry: entry.clone(),
                        depth: graph.depth[i] as u64,
                        clock,
                    }
                })
                .collect();
            let actual = crate::membership::resolve(&self.vault, nodes.iter().collect());
            assert_eq!(
                actual.members().copied().collect::<BTreeSet<_>>(),
                expected.members
            );
            assert_eq!(actual.name(), expected.name);
            for key in &self.keys {
                let device = key.device_id();
                for seq in 0..=2 {
                    assert_eq!(
                        actual.counts(&device, seq),
                        expected.members.contains(&device)
                            || expected
                                .cutoffs
                                .get(&device)
                                .is_some_and(|c| c.is_some_and(|cut| seq <= cut))
                    );
                }
            }
        }

        // Each extension with the model's verdict on applying it.
        fn extensions(&self, entries: &[Entry]) -> Vec<(Entry, Result<bool, Error>)> {
            let graph = Graph::new(entries);
            let last = (entries.len() > self.start).then(|| {
                let i = graph.entries.len() - 1;
                let e = graph.entries[i];
                order(graph.depth[i], &e.author(), e.deps(), e.payload())
            });
            let membership: Vec<_> = (0..entries.len())
                .filter(|&i| entries[i].log() == Log::Membership)
                .collect();
            let mut candidates = Vec::new();
            for mask in 1usize..1 << membership.len() {
                let parents: Vec<_> = (0..membership.len())
                    .filter(|bit| mask & (1 << bit) != 0)
                    .map(|bit| membership[bit])
                    .collect();
                if parents
                    .iter()
                    .any(|&i| parents.iter().any(|&j| graph.past[j].contains(&i)))
                {
                    continue;
                }
                let ancestors = graph.closure(parents.iter().map(|&i| entries[i].hash()));
                let state = self.model(entries, &ancestors);
                for author in &self.keys {
                    if !state.members.contains(&author.device_id()) {
                        continue;
                    }
                    let mut payloads = vec![
                        Payload::Membership(MembershipOp::Rename {
                            name: format!("name-{}", entries.len()),
                        }),
                        data(),
                    ];
                    for target in &self.keys {
                        if target.device_id() != author.device_id() {
                            payloads.push(Payload::Membership(MembershipOp::Add {
                                device: target.device_id(),
                                consent: self.consents[&(target.device_id(), author.device_id())],
                            }));
                        }
                        // Rejected removals differ in nothing that matters.
                        let cutoffs: &[_] = if state.members.contains(&target.device_id()) {
                            &[None, Some(0)]
                        } else {
                            &[None]
                        };
                        for &last_seen_seq in cutoffs {
                            payloads.push(Payload::Membership(MembershipOp::Remove {
                                device: target.device_id(),
                                last_seen_seq,
                            }));
                        }
                    }
                    for payload in payloads {
                        let log = payload.log();
                        let previous = entries.iter().rposition(|e| {
                            e.log_id()
                                == LogId {
                                    author: author.device_id(),
                                    log,
                                }
                        });
                        // The public API requires the previous entry as a direct
                        // dep. Keep membership parents exact; data entries also
                        // build on the author's previous data entry.
                        if log == Log::Membership
                            && previous.is_some_and(|p| !ancestors.contains(&p))
                        {
                            continue;
                        }
                        let deps: BTreeSet<_> = parents
                            .iter()
                            .copied()
                            .chain(previous)
                            .map(|i| entries[i].hash())
                            .collect();
                        let depth = deps
                            .iter()
                            .map(|hash| {
                                let i = graph.entries.iter().position(|e| e.hash() == *hash);
                                graph.depth[i.unwrap()] + 1
                            })
                            .max()
                            .unwrap();
                        let deps_list: Vec<_> = deps.iter().copied().collect();
                        let author_id = author.device_id();
                        if last.as_ref().is_some_and(|last| {
                            order(depth, &author_id, &deps_list, &payload) <= *last
                        }) {
                            continue;
                        }
                        let candidate = (author_id, previous, deps, payload);
                        if !candidates.contains(&candidate) {
                            candidates.push(candidate);
                        }
                    }
                }
            }
            // Judge before signing: signatures dominate the cost in debug builds.
            candidates
                .into_iter()
                .filter_map(|(author, previous, deps, payload)| {
                    let past = graph.closure(deps.iter().copied());
                    let state = self.model(entries, &past);
                    let verdict = match &payload {
                        // A data entry's previous write can reveal its
                        // author's removal; such entries are not explored.
                        _ if !state.members.contains(&author) => return None,
                        Payload::Membership(MembershipOp::Remove { device, .. })
                            if !state.members.contains(device) =>
                        {
                            Err(Error::RemoveNonMember)
                        }
                        _ => Ok(true),
                    };
                    let seq = previous.map_or(0, |p| entries[p].seq() + 1);
                    let secret = self.keys.iter().find(|k| k.device_id() == author)?;
                    let entry = Entry::sign(secret, self.vault, seq, deps, payload);
                    Some((entry, verdict))
                })
                .collect()
        }

        fn visit(&mut self, entries: &mut Vec<Entry>, vault: &mut Vault, left: usize) {
            self.histories += 1;
            self.check(entries, Some(vault));
            if left == 0 {
                return;
            }
            for (entry, verdict) in self.extensions(entries) {
                entries.push(entry.clone());
                match verdict {
                    Ok(_) => {
                        let mut child = vault.clone();
                        assert_eq!(child.apply(entry), Ok(true));
                        self.visit(entries, &mut child, left - 1);
                    }
                    // The API rejects it, so it heads no stored history. The
                    // resolver must still cope with it.
                    Err(error) => {
                        assert_eq!(vault.apply(entry), Err(error));
                        self.histories += 1;
                        self.check(entries, None);
                    }
                }
                entries.pop();
            }
        }
    }

    let keys: Vec<_> = (1..=3).map(key).collect();
    let mut invited = load(&[genesis(&keys[0])]);
    invited
        .add(
            &keys[0],
            keys[1].device_id(),
            consent(&keys[1], &invited, &keys[0]),
        )
        .unwrap();
    let invited = all(&invited);
    let consents = keys
        .iter()
        .flat_map(|device| {
            keys.iter().map(|inviter| {
                (
                    (device.device_id(), inviter.device_id()),
                    device.join_consent(&invited[0].vault(), &inviter.device_id()),
                )
            })
        })
        .collect();
    let mut search = Search {
        consents,
        keys,
        vault: invited[0].vault(),
        histories: 0,
        models: RefCell::default(),
        start: 0,
    };
    let depth = std::env::var("DEADBOLT_MEMBERSHIP_DEPTH")
        .ok()
        .map(|n| n.parse().expect("depth"))
        .unwrap_or(3);
    for root in [&invited[..1], &invited[..]] {
        search.start = root.len();
        search.visit(&mut root.to_vec(), &mut load(root), depth);
    }
    eprintln!(
        "exhaustive: {} histories, up to {depth} entries after the genesis or its first Add",
        search.histories
    );
}

// Run in release: `cargo test -p deadbolt-core --release -- --ignored large_vault`.
// On an idle machine the load takes about half a second, nearly all of it
// signature checks. Those slow down with the machine, so the budget covers the
// rest; before per-frontier caching that rest took over 30 s.
#[test]
#[ignore]
fn large_vault_loads_quickly() {
    let keys: Vec<_> = (1..=30).map(key).collect();
    let mut vault = load(&[genesis(&keys[0])]);
    let started = std::time::Instant::now();
    for k in &keys[1..20] {
        vault
            .add(&keys[0], k.device_id(), consent(k, &vault, &keys[0]))
            .unwrap();
    }
    let mut writers: Vec<usize> = (0..20).collect();
    for i in 0..5000 {
        let author = &keys[writers[i % writers.len()]];
        vault.commit(author, data()).unwrap();
        if i % 20 == 0 {
            vault.rename(author, format!("name-{i}")).unwrap();
        }
        if i % 500 == 250 {
            let gone = writers.remove(writers.len() - 1);
            vault.remove(&keys[0], keys[gone].device_id()).unwrap();
            let new = &keys[20 + i / 500];
            vault
                .add(&keys[0], new.device_id(), consent(new, &vault, &keys[0]))
                .unwrap();
            writers.insert(0, 20 + i / 500);
        }
    }
    let built = started.elapsed();
    let entries = all(&vault);
    let membership = entries
        .iter()
        .filter(|e| e.log() == Log::Membership)
        .count();
    let started = std::time::Instant::now();
    let loaded = load(&entries);
    let elapsed = started.elapsed();
    let started = std::time::Instant::now();
    entries.iter().for_each(|e| e.verify().unwrap());
    let signatures = started.elapsed();
    eprintln!(
        "{} entries ({membership} membership): built in {built:?}, loaded in {elapsed:?}, \
         of which checking signatures alone takes {signatures:?}",
        entries.len()
    );
    assert_eq!(loaded.items().len(), vault.items().len());
    let rest = elapsed.saturating_sub(signatures);
    assert!(rest < std::time::Duration::from_millis(250), "{rest:?}");
}

#[test]
fn sockpuppet_bypass() {
    let (a, b, c) = (key(1), key(2), key(3));
    let mut honest = load(&[genesis(&a)]);
    honest
        .add(&a, b.device_id(), consent(&b, &honest, &a))
        .unwrap();
    let mut thief = load(&all(&honest));
    // Delay A's removal beyond the attack's depth, avoiding hash-order luck.
    honest.rename(&a, "one").unwrap();
    honest.rename(&a, "two").unwrap();
    honest.remove(&a, b.device_id()).unwrap();
    thief
        .add(&b, c.device_id(), consent(&c, &thief, &b))
        .unwrap();
    thief.remove(&c, a.device_id()).unwrap();
    for entry in thief.entries() {
        honest.apply(entry.clone()).unwrap();
    }
    assert!(
        honest.is_member(&a.device_id()),
        "sockpuppet evicted creator"
    );
    assert!(!honest.is_member(&b.device_id()));
    assert!(!honest.is_member(&c.device_id()));
}

#[test]
fn three_way_cycle() {
    let (a, b, c) = (key(1), key(2), key(3));
    let mut base = load(&[genesis(&a)]);
    base.add(&a, b.device_id(), consent(&b, &base, &a)).unwrap();
    base.add(&a, c.device_id(), consent(&c, &base, &a)).unwrap();
    // Force B->C, C->A, A->B replay order by causal depth, not hash grinding.
    let entries = all(&base);
    let mut va = load(&entries);
    let mut vb = load(&entries);
    let mut vc = load(&entries);
    vb.remove(&b, c.device_id()).unwrap();
    vc.rename(&c, "c").unwrap();
    vc.remove(&c, a.device_id()).unwrap();
    va.rename(&a, "a1").unwrap();
    va.rename(&a, "a2").unwrap();
    va.remove(&a, b.device_id()).unwrap();
    let branches = [&va, &vb, &vc];
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let mut merged = load(&entries);
        for i in order {
            for entry in branches[i].entries() {
                merged.apply(entry.clone()).unwrap();
            }
        }
        assert!(merged.is_member(&a.device_id()), "cycle evicted creator");
        assert!(!merged.is_member(&b.device_id()));
        assert!(merged.is_member(&c.device_id()));
        assert_state(&merged, &all(&merged));
    }
}

#[test]
fn junior_can_remove_creator_but_cannot_race_senior_survivor() {
    let (a, b, c, d) = (key(1), key(2), key(3), key(4));
    let mut honest = load(&[genesis(&a)]);
    honest
        .add(&a, b.device_id(), consent(&b, &honest, &a))
        .unwrap();
    honest
        .add(&a, c.device_id(), consent(&c, &honest, &a))
        .unwrap();
    honest.remove(&b, a.device_id()).unwrap();
    assert!(
        !honest.is_member(&a.device_id()),
        "seniority is not immunity"
    );
    let mut thief = load(&all(&honest));
    honest.remove(&b, c.device_id()).unwrap();
    thief
        .add(&c, d.device_id(), consent(&d, &thief, &c))
        .unwrap();
    thief.remove(&d, b.device_id()).unwrap();
    for entry in thief.entries() {
        honest.apply(entry.clone()).unwrap();
    }
    assert_eq!(honest.members().collect::<Vec<_>>(), vec![b.device_id()]);
}

#[test]
fn removal_rejects_acknowledged_writes_and_neutralizes_hidden_parents() {
    let (a, b, c) = (key(1), key(2), key(3));
    let mut vault = load(&[genesis(&a)]);
    let admission = vault
        .add(&a, b.device_id(), consent(&b, &vault, &a))
        .unwrap();
    let remove = vault.remove(&a, b.device_id()).unwrap();
    let mut entries = all(&vault);
    for payload in [
        data(),
        Payload::Membership(MembershipOp::Add {
            device: c.device_id(),
            consent: consent(&c, &vault, &b),
        }),
        Payload::Membership(MembershipOp::Remove {
            device: a.device_id(),
            last_seen_seq: None,
        }),
    ] {
        let entry = Entry::sign(&b, vault.id(), 0, [remove.hash()], payload);
        assert_eq!(vault.apply(entry), Err(Error::NotMember));
    }
    let hidden_write = Entry::sign(&b, vault.id(), 0, [admission.hash()], data());
    let hidden_add = Entry::sign(
        &b,
        vault.id(),
        0,
        [admission.hash()],
        Payload::Membership(MembershipOp::Add {
            device: c.device_id(),
            consent: consent(&c, &vault, &b),
        }),
    );
    for entry in [hidden_write, hidden_add.clone()] {
        assert_eq!(vault.apply(entry.clone()), Ok(true));
        entries.push(entry);
    }
    assert!(!vault.is_member(&c.device_id()));
    assert!(vault.items().is_empty());
    // Merely having an Add in the past is not sufficient: the past resolves it
    // as cut by A, so C's claim of authority must fail before storage.
    let child = Entry::sign(
        &c,
        vault.id(),
        0,
        [remove.hash(), hidden_add.hash()],
        data(),
    );
    assert_eq!(vault.apply(child), Err(Error::NotMember));
    for seed in [1, 7, 123] {
        deliver(&entries, seed);
    }
}

#[test]
fn cut_admission_falls_back_to_surviving_add() {
    let (a, b, c) = (key(1), key(2), key(3));
    let mut vault = load(&[genesis(&a)]);
    vault
        .add(&a, b.device_id(), consent(&b, &vault, &a))
        .unwrap();
    let mut thief = load(&all(&vault));
    let add = thief
        .add(&b, c.device_id(), consent(&c, &thief, &b))
        .unwrap();
    vault.remove(&a, b.device_id()).unwrap();
    vault.rename(&a, "later").unwrap();
    vault
        .add(&a, c.device_id(), consent(&c, &vault, &a))
        .unwrap();
    vault.apply(add).unwrap();
    assert!(vault.is_member(&c.device_id()));
    assert_state(&vault, &all(&vault));
}

// Review finding: T lifted the consent from N's Add by A to re-add N with old
// parents, so its Add became N's first and was cut by T's removal.
#[test]
fn lifted_consent_cannot_back_another_add() {
    let (a, t, n) = (key(1), key(2), key(3));
    let mut vault = load(&[genesis(&a)]);
    let add_t = vault
        .add(&a, t.device_id(), consent(&t, &vault, &a))
        .unwrap();
    let add_n = vault
        .add(&a, n.device_id(), consent(&n, &vault, &a))
        .unwrap();
    let Payload::Membership(MembershipOp::Add {
        consent: lifted, ..
    }) = add_n.payload()
    else {
        unreachable!()
    };
    let forged = Entry::sign(
        &t,
        vault.id(),
        0,
        [add_t.hash()],
        Payload::Membership(MembershipOp::Add {
            device: n.device_id(),
            consent: *lifted,
        }),
    );
    assert_eq!(vault.apply(forged), Err(Error::InvalidConsent));
}

// The same race with consent N really gave T (say a pairing with T failed after
// T wrote its Add, and N retried with A). T's shallow Add is N's first
// admission and is cut when A removes T; A's Add must keep N a member.
#[test]
fn duplicate_add_never_strips_membership() {
    let (a, t, n) = (key(1), key(2), key(3));
    let mut vault = load(&[genesis(&a)]);
    let add_t = vault
        .add(&a, t.device_id(), consent(&t, &vault, &a))
        .unwrap();
    let early = Entry::sign(
        &t,
        vault.id(),
        0,
        [add_t.hash()],
        Payload::Membership(MembershipOp::Add {
            device: n.device_id(),
            consent: consent(&n, &vault, &t),
        }),
    );
    vault.rename(&a, "x").unwrap();
    vault.rename(&a, "y").unwrap();
    vault
        .add(&a, n.device_id(), consent(&n, &vault, &a))
        .unwrap();
    vault.commit(&n, data()).unwrap();
    vault.remove(&a, t.device_id()).unwrap();
    vault.apply(early).unwrap();
    assert!(vault.is_member(&n.device_id()), "a cut duplicate evicted N");
    assert_eq!(vault.items().len(), 1, "N's data vanished");
    // Every arrival order, including the duplicate before the removal.
    for seed in [1, 2, 3, 4] {
        deliver(&all(&vault), seed);
    }
}

#[test]
fn removing_a_non_member_is_rejected() {
    let (a, b, c) = (key(1), key(2), key(3));
    let mut vault = load(&[genesis(&a)]);
    vault
        .add(&a, b.device_id(), consent(&b, &vault, &a))
        .unwrap();
    assert_eq!(
        vault.remove(&a, c.device_id()),
        Err(Error::RemoveNonMember),
        "never added"
    );
    vault.remove(&a, b.device_id()).unwrap();
    let heads = vault.heads();
    assert_eq!(
        vault.remove(&a, b.device_id()),
        Err(Error::RemoveNonMember),
        "already removed"
    );
    assert_eq!(vault.heads(), heads);
}

#[test]
fn known_limitation_removed_senior_returns_with_hidden_parents() {
    let (a, b) = (key(1), key(2));
    let mut vault = load(&[genesis(&a)]);
    let add_b = vault
        .add(&a, b.device_id(), consent(&b, &vault, &a))
        .unwrap();
    vault.remove(&b, a.device_id()).unwrap();
    assert!(!vault.is_member(&a.device_id()));
    let hidden = Entry::sign(
        &a,
        vault.id(),
        2,
        [add_b.hash()],
        Payload::Membership(MembershipOp::Remove {
            device: b.device_id(),
            last_seen_seq: None,
        }),
    );
    vault.apply(hidden).unwrap();
    // A, senior to B, wins the race it staged with old parents.
    assert!(vault.is_member(&a.device_id()));
    assert!(!vault.is_member(&b.device_id()));
    assert_state(&vault, &all(&vault));
}

#[test]
fn known_limitation_cut_first_add_keeps_seniority() {
    let (a, b, h, c, p) = (key(1), key(2), key(3), key(4), key(5));
    let mut vault = load(&[genesis(&a)]);
    let add_b = vault
        .add(&a, b.device_id(), consent(&b, &vault, &a))
        .unwrap();
    // B's hidden Add of P sits just below B, above H and C.
    let hidden = Entry::sign(
        &b,
        vault.id(),
        0,
        [add_b.hash()],
        Payload::Membership(MembershipOp::Add {
            device: p.device_id(),
            consent: consent(&p, &vault, &b),
        }),
    );
    vault.rename(&a, "x").unwrap();
    vault
        .add(&a, h.device_id(), consent(&h, &vault, &a))
        .unwrap();
    vault
        .add(&a, c.device_id(), consent(&c, &vault, &a))
        .unwrap();
    vault.remove(&a, b.device_id()).unwrap();
    vault.apply(hidden).unwrap();
    vault
        .add(&c, p.device_id(), consent(&p, &vault, &c))
        .unwrap();
    let mut puppet = load(&all(&vault));
    vault.remove(&h, p.device_id()).unwrap();
    puppet.remove(&p, h.device_id()).unwrap();
    for entry in puppet.entries() {
        vault.apply(entry.clone()).unwrap();
    }
    // P keeps the rank of its cut Add by B and beats H.
    assert!(vault.is_member(&p.device_id()));
    assert!(!vault.is_member(&h.device_id()));
    assert_state(&vault, &all(&vault));
}
