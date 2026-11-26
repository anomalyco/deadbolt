//! What a vault takes from peers: only frames signed by keys its
//! membership names, and from a removed device a bounded number of frames
//! that don't count.

use super::{Peer, first, login, pair};
use crate::v2::{DeviceKeys, Frame, FrameId, LogKind, MemberBody, MemberOp, sign_join_consent};
use crate::vault::MAX_REMOVED_UNAUTHORIZED;
use crate::vault::testing::author;
use crate::{Author, Error, VaultId};

fn offer(to: &mut Peer, frames: Vec<Frame>) -> usize {
    let kem = to.a.keys().kem_key();
    to.v.transact(|w| w.apply(kem, frames), |_, _| Ok::<_, Error>(()))
        .unwrap()
}

/// An `Add` of a fresh device, signed by `signer` whatever it is.
fn forged_add(
    vault: VaultId,
    signer: &Author,
    seq: u64,
    prev: FrameId,
    deps: Vec<FrameId>,
    joiner: u32,
) -> Frame {
    let mut seed = [0x5a; 32];
    seed[..4].copy_from_slice(&joiner.to_be_bytes());
    let joiner = DeviceKeys::from_seed(&seed);
    let body = MemberBody {
        deps,
        op: Some(MemberOp::Add {
            device: joiner.device_id(),
            kem: joiner.kem_public(),
            consent: sign_join_consent(&joiner, &vault, &signer.id()),
            rewrap: None,
        }),
        rotate: None,
    };
    Frame::sign_member(signer.keys().sign_key(), vault, seq, prev, body).unwrap()
}

fn genesis(p: &Peer) -> FrameId {
    p.v.frames()
        .find(|f| f.header().kind.log_kind() == LogKind::Member && f.header().seq == 0)
        .unwrap()
        .id()
}

fn remove(by: &mut Peer, device: crate::DeviceId) -> FrameId {
    let (a, v) = (&by.a, &mut by.v);
    v.transact(|w| w.remove(a, device), |_, _| Ok::<_, Error>(()))
        .unwrap()
}

#[test]
fn a_key_no_membership_names_cannot_store_frames() {
    let mut a = first();
    let stranger = author(9);
    let forged = forged_add(a.v.id(), &stranger, 0, FrameId::ZERO, vec![genesis(&a)], 1);
    assert_eq!(offer(&mut a, vec![forged.clone()]), 0);
    assert!(a.v.frame(&forged.id()).is_none());
}

#[test]
fn a_removed_device_stores_a_bounded_number_of_data_frames_past_its_removal() {
    let mut a = first();
    let mut b = pair(&mut a, 2);
    // b writes what a never saw, then a removes it.
    for i in 0..(MAX_REMOVED_UNAUTHORIZED + 20) {
        b.v.create_item(&b.a, "login", Some(format!("late {i}")), login("u", "p"))
            .unwrap();
    }
    remove(&mut a, b.a.id());
    let late: Vec<Frame> =
        b.v.missing(&a.v.heads(), LogKind::Data)
            .into_iter()
            .filter(|f| f.header().author == b.a.id())
            .cloned()
            .collect();
    assert!(late.len() > MAX_REMOVED_UNAUTHORIZED);
    offer(&mut a, late.clone());
    let held = late.iter().filter(|f| a.v.frame(&f.id()).is_some()).count();
    assert_eq!(held, MAX_REMOVED_UNAUTHORIZED);
    // None of it counts.
    assert!(a.v.items().is_empty());
}

#[test]
fn a_removed_device_stores_a_bounded_number_of_membership_frames() {
    let mut a = first();
    let b = pair(&mut a, 2);
    let removal = remove(&mut a, b.a.id());
    // The stolen device signs a long chain of adds after its removal.
    let (mut prev, mut spam) = (FrameId::ZERO, Vec::new());
    for seq in 0..(MAX_REMOVED_UNAUTHORIZED as u64 + 50) {
        let mut deps = vec![removal];
        if !prev.is_zero() {
            deps.push(prev);
            deps.sort();
        }
        let frame = forged_add(a.v.id(), &b.a, seq, prev, deps, seq as u32);
        prev = frame.id();
        spam.push(frame);
    }
    offer(&mut a, spam);
    let held =
        a.v.frames()
            .filter(|f| f.header().author == b.a.id())
            .count();
    assert!(held <= MAX_REMOVED_UNAUTHORIZED, "{held}");
    // Nor does anyone its adds name become a signer.
    assert!(a.v.members().all(|d| d == a.a.id()));
}
