//! Membership security specification (design.md, Membership / Removing a device).
//!
//! Admissions are ordered by (causal depth, entry hash). Removed keys cannot
//! rejoin. A removal cuts every membership operation by its target that it did
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

#[test]
#[ignore = "reproduced on main: sockpuppet evicts creator"]
fn sockpuppet_bypass() {
    let (a, b, c) = (key(1), key(2), key(3));
    let mut honest = load(&[genesis(&a)]);
    honest
        .add(&a, b.device_id(), b.join_consent(&honest.id()))
        .unwrap();
    let mut thief = load(&honest.entries().into_iter().cloned().collect::<Vec<_>>());
    // Delay A's removal beyond the attack's depth, avoiding hash-order luck.
    honest.rename(&a, "one").unwrap();
    honest.rename(&a, "two").unwrap();
    honest.remove(&a, b.device_id()).unwrap();
    thief
        .add(&b, c.device_id(), c.join_consent(&thief.id()))
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
#[ignore = "reproduced on main: three-way cycle evicts creator"]
fn three_way_cycle() {
    let (a, b, c) = (key(1), key(2), key(3));
    let mut base = load(&[genesis(&a)]);
    base.add(&a, b.device_id(), b.join_consent(&base.id()))
        .unwrap();
    base.add(&a, c.device_id(), c.join_consent(&base.id()))
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
    for v in [&vb, &vc, &va] {
        for entry in v.entries() {
            base.apply(entry.clone()).unwrap();
        }
    }
    assert!(base.is_member(&a.device_id()), "cycle evicted creator");
    assert!(!base.is_member(&b.device_id()));
    assert!(base.is_member(&c.device_id()));
}
