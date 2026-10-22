//! Membership security specification (design.md, Membership / Removing a device).
//!
//! Admissions are ordered by (causal depth, entry hash). Removed keys cannot
//! rejoin; the first structurally authorized Add is canonical even if cut, so
//! another Add cannot resurrect its key. A removal cuts every membership
//! operation by its target that it did
//! not observe, including authority delegated through an arbitrary Add chain.
//! Observed additions survive the inviter's removal.
//!
//! Judgment call: generalize mutual-removal seniority to ALL conflicting
//! removals, including longer cycles. Consider removals in their authors'
//! admission order (then operation depth/hash). Keep a removal only if its cuts
//! leave it and every previously chosen removal authorized. Thus a junior
//! cannot undo a senior's removal by removing its author or cutting an admission
//! that authorized it. Unrelated removals coexist; causal removals remain final.
//! Cutoffs from concurrent chosen removals of one key are combined by maximum.
//!
//! Admission/operation validity is causal, never arrival-dependent. An entry
//! whose ancestors already remove its author is rejected. An attacker can hide
//! knowledge using old parents: that is indistinguishable from an offline write
//! and may be stored, but its effects beyond the removal's cutoff are ignored.
//! Delivery order must not affect membership, names, or visible data.

use crate::*;
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

// Independent oracle: explicit transitive closure of hashes (no Node, Clock,
// saw, replay, or production resolver), then exhaustive search of removal sets.
// Select the lexicographically greatest authorized subset in seniority order.
// This is deliberately exponential and suitable only for small test histories.
#[derive(Debug, PartialEq, Eq)]
struct Model {
    members: BTreeSet<DeviceId>,
    cutoffs: BTreeMap<DeviceId, Option<u64>>,
    name: String,
}

struct Graph<'a> {
    entries: Vec<&'a Entry>,
    past: Vec<BTreeSet<usize>>,
    depth: Vec<usize>,
    admission: BTreeMap<DeviceId, usize>,
}

impl<'a> Graph<'a> {
    fn new(entries: &'a [Entry]) -> Self {
        let mut graph = Self {
            entries: Vec::new(),
            past: Vec::new(),
            depth: Vec::new(),
            admission: BTreeMap::new(),
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
        let mut order: Vec<_> = (0..entries.len()).collect();
        order.sort_by_key(|&i| (graph.depth[i], graph.entries[i].hash()));
        for i in order {
            let e = graph.entries[i];
            match e.payload() {
                Payload::Membership(MembershipOp::Create { device, .. }) => {
                    graph.admission.insert(*device, i);
                }
                Payload::Membership(MembershipOp::Add { device, .. })
                    if graph
                        .admission
                        .get(&e.author())
                        .is_some_and(|own| graph.past[i].contains(own)) =>
                {
                    graph.admission.entry(*device).or_insert(i);
                }
                _ => {}
            }
        }
        graph
    }

    fn target(&self, i: usize) -> DeviceId {
        match self.entries[i].payload() {
            Payload::Membership(MembershipOp::Remove { device, .. }) => *device,
            _ => panic!("not a removal"),
        }
    }

    // Walk authority back to genesis, independently of chronological replay.
    fn authorized(&self, i: usize, removals: &[usize]) -> bool {
        let e = self.entries[i];
        if matches!(
            e.payload(),
            Payload::Membership(MembershipOp::Create { .. })
        ) {
            return true;
        }
        if removals
            .iter()
            .any(|&r| r != i && self.target(r) == e.author() && !self.past[r].contains(&i))
        {
            return false;
        }
        self.admission
            .get(&e.author())
            .is_some_and(|&own| self.past[i].contains(&own) && self.authorized(own, removals))
    }

    fn valid_set(&self, removals: &[usize]) -> bool {
        removals.iter().all(|&r| {
            self.authorized(r, removals)
                && self
                    .admission
                    .get(&self.target(r))
                    .is_some_and(|&a| self.past[r].contains(&a) && self.authorized(a, removals))
                && !removals.iter().any(|&other| {
                    self.target(other) == self.target(r) && self.past[r].contains(&other)
                })
        })
    }

    fn model(&self) -> Model {
        let mut candidates: Vec<_> = (0..self.entries.len())
            .filter(|&i| {
                matches!(
                    self.entries[i].payload(),
                    Payload::Membership(MembershipOp::Remove { .. })
                ) && self.admission.contains_key(&self.entries[i].author())
            })
            .collect();
        candidates.sort_by_key(|&i| {
            let a = self.admission[&self.entries[i].author()];
            (
                self.depth[a],
                self.entries[a].hash(),
                self.depth[i],
                self.entries[i].hash(),
            )
        });
        assert!(candidates.len() < 16, "oracle is exponential");
        let removals = (0..1usize << candidates.len())
            .rev()
            .find_map(|mask| {
                let selected: Vec<_> = candidates
                    .iter()
                    .enumerate()
                    .filter(|(bit, _)| mask & (1 << (candidates.len() - 1 - bit)) != 0)
                    .map(|(_, &i)| i)
                    .collect();
                self.valid_set(&selected).then_some(selected)
            })
            .unwrap();
        let mut members: BTreeSet<_> = self
            .admission
            .iter()
            .filter(|&(_, &i)| self.authorized(i, &removals))
            .map(|(&key, _)| key)
            .collect();
        let mut cutoffs: BTreeMap<DeviceId, Option<u64>> = BTreeMap::new();
        for &r in &removals {
            if let Payload::Membership(MembershipOp::Remove {
                device,
                last_seen_seq,
            }) = self.entries[r].payload()
            {
                members.remove(device);
                let cutoff = cutoffs.entry(*device).or_default();
                *cutoff = (*cutoff).max(*last_seen_seq);
            }
        }
        let names: Vec<_> = (0..self.entries.len())
            .filter(|&i| {
                matches!(
                    self.entries[i].payload(),
                    Payload::Membership(MembershipOp::Create { .. } | MembershipOp::Rename { .. })
                ) && self.authorized(i, &removals)
            })
            .collect();
        let winner = names
            .iter()
            .copied()
            .filter(|&i| !names.iter().any(|&j| self.past[j].contains(&i)))
            .max_by_key(|&i| self.entries[i].hash())
            .unwrap();
        let name = match self.entries[winner].payload() {
            Payload::Membership(
                MembershipOp::Create { name, .. } | MembershipOp::Rename { name },
            ) => name.clone(),
            _ => unreachable!(),
        };
        Model {
            members,
            cutoffs,
            name,
        }
    }
}

fn model(entries: &[Entry]) -> Model {
    Graph::new(entries).model()
}

fn key(n: u8) -> DeviceSecret {
    DeviceSecret::from_bytes(&[n; 32])
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

fn assert_state(vault: &Vault, entries: &[Entry]) {
    let expected = model(entries);
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

// Every attempted entry has a real signature and valid consent. Parent choice
// deliberately forks old snapshots, but always includes the previous same-log
// entry. The oracle decides causal authorization; the real API must agree.
fn history(devices: usize, steps: &[(u8, u8, u8, u16)]) -> Vec<Entry> {
    let keys: Vec<_> = (1..=devices as u8).map(key).collect();
    let mut vault = load(&[genesis(&keys[0])]);
    vault
        .add(
            &keys[0],
            keys[1].device_id(),
            keys[1].join_consent(&vault.id(), &keys[0].device_id()),
        )
        .unwrap();
    let mut entries: Vec<_> = vault.entries().into_iter().cloned().collect();
    for &(author, target, kind, branch) in steps {
        let author = &keys[author as usize % devices];
        let target = &keys[target as usize % devices];
        let payload = match kind % 4 {
            0 => Payload::Membership(MembershipOp::Add {
                device: target.device_id(),
                consent: target.join_consent(&vault.id(), &author.device_id()),
            }),
            1 => Payload::Membership(MembershipOp::Remove {
                device: target.device_id(),
                last_seen_seq: (branch % 3).checked_sub(1).map(u64::from),
            }),
            2 => Payload::Membership(MembershipOp::Rename {
                name: format!("name-{branch}"),
            }),
            _ => data(),
        };
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
        let graph = Graph::new(&entries);
        let ancestors: BTreeSet<_> = deps
            .iter()
            .flat_map(|hash| {
                let i = graph
                    .entries
                    .iter()
                    .position(|e| e.hash() == *hash)
                    .unwrap();
                graph.past[i].iter().copied().chain(std::iter::once(i))
            })
            .collect();
        let past: Vec<_> = ancestors
            .into_iter()
            .map(|i| graph.entries[i].clone())
            .collect();
        let allowed = model(&past).members.contains(&author.device_id());
        let entry = Entry::sign(
            author,
            vault.id(),
            previous.map_or(0, |e| e.seq() + 1),
            deps,
            payload,
        );
        let result = vault.apply(entry.clone());
        assert_eq!(
            result,
            if allowed {
                Ok(true)
            } else {
                Err(Error::NotMember)
            }
        );
        if allowed {
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
    fn signed_histories_converge_to_oracle(
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
        honest.add(&keys[0], keys[1].device_id(), keys[1].join_consent(&honest.id(), &keys[0].device_id())).unwrap();
        let mut thief = load(&honest.entries().into_iter().cloned().collect::<Vec<_>>());
        for i in 0..delay { honest.rename(&keys[0], format!("name-{salt}-{i}")).unwrap(); }
        honest.remove(&keys[0], keys[1].device_id()).unwrap();
        for i in 1..=hops { thief.add(&keys[i], keys[i + 1].device_id(), keys[i + 1].join_consent(&thief.id(), &keys[i].device_id())).unwrap(); }
        thief.remove(&keys[hops + 1], keys[0].device_id()).unwrap();
        let mut entries: Vec<_> = honest.entries().into_iter().cloned().collect();
        for entry in thief.entries() { if !entries.iter().any(|e| e.hash() == entry.hash()) { entries.push(entry.clone()); } }
        for order in [salt, !salt] { deliver(&entries, order); }
        assert_eq!(model(&entries).members, BTreeSet::from([keys[0].device_id()]));
    }
}

#[test]
fn exhaustive_small_membership_dags() {
    fn check(entries: &[Entry]) {
        let graph = Graph::new(entries);
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
        let actual = crate::membership::resolve(&entries[0].vault(), nodes.iter().collect());
        let expected = graph.model();
        assert_eq!(
            actual.members().copied().collect::<BTreeSet<_>>(),
            expected.members
        );
        assert_eq!(actual.name(), expected.name);
        for key in (1..=3).map(key) {
            for seq in 0..=2 {
                assert_eq!(
                    actual.counts(&key.device_id(), seq),
                    expected.members.contains(&key.device_id())
                        || expected
                            .cutoffs
                            .get(&key.device_id())
                            .is_some_and(|c| c.is_some_and(|cut| seq <= cut))
                );
            }
        }
    }

    fn visit(entries: &mut Vec<Entry>, keys: &[DeviceSecret], left: usize, count: &mut usize) {
        *count += 1;
        check(entries);
        if left == 0 {
            return;
        }
        let graph = Graph::new(entries);
        let mut extensions = Vec::new();
        // Enumerate every causal parent antichain, every author and every legal
        // Add/Remove target, including self-removal, with three fixed keys.
        // Redundant parents and no-op Adds/Removes are covered by proptest.
        for mask in 1usize..1 << entries.len() {
            let parents: Vec<_> = (0..entries.len())
                .filter(|i| mask & (1 << i) != 0)
                .collect();
            if parents
                .iter()
                .any(|&i| parents.iter().any(|&j| graph.past[j].contains(&i)))
            {
                continue;
            }
            let ancestors: BTreeSet<_> = parents
                .iter()
                .flat_map(|&i| graph.past[i].iter().copied().chain(std::iter::once(i)))
                .collect();
            let past: Vec<_> = ancestors.iter().map(|&i| entries[i].clone()).collect();
            let state = model(&past);
            for author in keys {
                if !state.members.contains(&author.device_id()) {
                    continue;
                }
                let previous = entries
                    .iter()
                    .rposition(|e| e.author() == author.device_id());
                // The public API requires the previous entry as a direct dep,
                // even when another parent already implies it.
                let deps: BTreeSet<_> = parents
                    .iter()
                    .copied()
                    .chain(previous)
                    .map(|i| entries[i].hash())
                    .collect();
                if previous.is_some_and(|p| !ancestors.contains(&p)) {
                    continue;
                }
                for target in keys {
                    let op = if state.members.contains(&target.device_id()) {
                        MembershipOp::Remove {
                            device: target.device_id(),
                            last_seen_seq: None,
                        }
                    } else if !graph.admission.contains_key(&target.device_id()) {
                        MembershipOp::Add {
                            device: target.device_id(),
                            consent: target.join_consent(&entries[0].vault(), &author.device_id()),
                        }
                    } else {
                        continue;
                    };
                    extensions.push(Entry::sign(
                        author,
                        entries[0].vault(),
                        previous.map_or(0, |p| entries[p].seq() + 1),
                        deps.iter().copied(),
                        Payload::Membership(op),
                    ));
                }
            }
        }
        extensions.sort_by_key(Entry::hash);
        extensions.dedup_by_key(|e| e.hash());
        for entry in extensions {
            entries.push(entry);
            visit(entries, keys, left - 1, count);
            entries.pop();
        }
    }

    let keys: Vec<_> = (1..=3).map(key).collect();
    let depth = std::env::var("DEADBOLT_MEMBERSHIP_DEPTH")
        .ok()
        .map(|n| n.parse().expect("depth"))
        .unwrap_or(4);
    let mut count = 0;
    visit(&mut vec![genesis(&keys[0])], &keys, depth, &mut count);
    eprintln!("exhaustive: {count} histories, up to {depth} operations after genesis");
}

#[test]
fn sockpuppet_bypass() {
    let (a, b, c) = (key(1), key(2), key(3));
    let mut honest = load(&[genesis(&a)]);
    honest
        .add(
            &a,
            b.device_id(),
            b.join_consent(&honest.id(), &a.device_id()),
        )
        .unwrap();
    let mut thief = load(&honest.entries().into_iter().cloned().collect::<Vec<_>>());
    // Delay A's removal beyond the attack's depth, avoiding hash-order luck.
    honest.rename(&a, "one").unwrap();
    honest.rename(&a, "two").unwrap();
    honest.remove(&a, b.device_id()).unwrap();
    thief
        .add(
            &b,
            c.device_id(),
            c.join_consent(&thief.id(), &b.device_id()),
        )
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
    base.add(
        &a,
        b.device_id(),
        b.join_consent(&base.id(), &a.device_id()),
    )
    .unwrap();
    base.add(
        &a,
        c.device_id(),
        c.join_consent(&base.id(), &a.device_id()),
    )
    .unwrap();
    // Force B->C, C->A, A->B replay order by causal depth, not hash grinding.
    let entries: Vec<_> = base.entries().into_iter().cloned().collect();
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
        assert_state(
            &merged,
            &merged.entries().into_iter().cloned().collect::<Vec<_>>(),
        );
    }
}

#[test]
fn junior_can_remove_creator_but_cannot_race_senior_survivor() {
    let (a, b, c, d) = (key(1), key(2), key(3), key(4));
    let mut honest = load(&[genesis(&a)]);
    honest
        .add(
            &a,
            b.device_id(),
            b.join_consent(&honest.id(), &a.device_id()),
        )
        .unwrap();
    honest
        .add(
            &a,
            c.device_id(),
            c.join_consent(&honest.id(), &a.device_id()),
        )
        .unwrap();
    honest.remove(&b, a.device_id()).unwrap();
    assert!(
        !honest.is_member(&a.device_id()),
        "seniority is not immunity"
    );
    let mut thief = load(&honest.entries().into_iter().cloned().collect::<Vec<_>>());
    honest.remove(&b, c.device_id()).unwrap();
    thief
        .add(
            &c,
            d.device_id(),
            d.join_consent(&thief.id(), &c.device_id()),
        )
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
        .add(
            &a,
            b.device_id(),
            b.join_consent(&vault.id(), &a.device_id()),
        )
        .unwrap();
    let remove = vault.remove(&a, b.device_id()).unwrap();
    let mut entries: Vec<_> = vault.entries().into_iter().cloned().collect();
    for payload in [
        data(),
        Payload::Membership(MembershipOp::Add {
            device: c.device_id(),
            consent: c.join_consent(&vault.id(), &b.device_id()),
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
            consent: c.join_consent(&vault.id(), &b.device_id()),
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
fn cut_admission_cannot_fall_back_to_another_add() {
    let (a, b, c) = (key(1), key(2), key(3));
    let mut vault = load(&[genesis(&a)]);
    vault
        .add(
            &a,
            b.device_id(),
            b.join_consent(&vault.id(), &a.device_id()),
        )
        .unwrap();
    let mut thief = load(&vault.entries().into_iter().cloned().collect::<Vec<_>>());
    let add = thief
        .add(
            &b,
            c.device_id(),
            c.join_consent(&vault.id(), &b.device_id()),
        )
        .unwrap();
    vault.remove(&a, b.device_id()).unwrap();
    vault.rename(&a, "later").unwrap();
    vault
        .add(
            &a,
            c.device_id(),
            c.join_consent(&vault.id(), &a.device_id()),
        )
        .unwrap();
    vault.apply(add).unwrap();
    assert!(!vault.is_member(&c.device_id()));
    assert_state(
        &vault,
        &vault.entries().into_iter().cloned().collect::<Vec<_>>(),
    );
}

// Review finding: T lifted the consent from N's Add by A to re-add N with old
// parents, so its Add became N's first and was cut by T's removal.
#[test]
fn lifted_consent_cannot_back_another_add() {
    let (a, t, n) = (key(1), key(2), key(3));
    let mut vault = load(&[genesis(&a)]);
    let add_t = vault
        .add(
            &a,
            t.device_id(),
            t.join_consent(&vault.id(), &a.device_id()),
        )
        .unwrap();
    let add_n = vault
        .add(
            &a,
            n.device_id(),
            n.join_consent(&vault.id(), &a.device_id()),
        )
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
