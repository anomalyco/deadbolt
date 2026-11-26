//! The recovery root after a mutual removal: device parking never stops it,
//! and its removal of one side settles the pair.

use super::{Peer, first, pair, sync};
use crate::v2::{Frame, LogKind, ParkingReason};
use crate::vault::testing::{author, recovery};
use crate::{Error, Vault};

/// `b` and `c` remove each other offline; `a` hears both and parks.
fn mutual() -> (Peer, Peer, Peer) {
    let mut a = first();
    let mut b = pair(&mut a, 2);
    let mut c = pair(&mut a, 3);
    sync(&a, &mut b);
    sync(&a, &mut c);
    let (ba, cid, bid) = (&b.a, c.a.id(), b.a.id());
    b.v.transact(|w| w.remove(ba, cid), |_, _| Ok::<_, Error>(()))
        .unwrap();
    let ca = &c.a;
    c.v.transact(|w| w.remove(ca, bid), |_, _| Ok::<_, Error>(()))
        .unwrap();
    sync(&b, &mut a);
    sync(&c, &mut a);
    assert!(
        a.v.parked()
            .iter()
            .any(|r| matches!(r, ParkingReason::MutualRemoval { .. }))
    );
    (a, b, c)
}

fn as_root(p: &Peer) -> Vault {
    let rs = recovery();
    Vault::open_as(rs.recovery_id(), &rs.kem_secret(), p.v.frames().cloned()).unwrap()
}

#[test]
fn the_root_adds_a_device_while_devices_are_parked() {
    let (a, _, _) = mutual();
    let mut root = as_root(&a);
    let (rs, d) = (recovery(), author(9));
    let consent = d.join_consent(&root.id(), &rs.recovery_id());
    root.transact(
        |w| {
            w.add_signed(&rs.signing_key(), d.id(), d.keys().kem_public(), consent)?;
            w.root_reader_duty(&rs)
        },
        |_, _| Ok::<_, Error>(()),
    )
    .unwrap();
    assert!(root.is_member(&d.id()));
}

#[test]
fn a_root_removal_after_both_settles_a_mutual_removal() {
    let (mut a, b, _) = mutual();
    let mut root = as_root(&a);
    let rs = recovery();
    root.transact(
        |w| w.remove_by_root(&rs, b.a.id()),
        |_, _| Ok::<_, Error>(()),
    )
    .unwrap();
    let frames: Vec<Frame> = root
        .missing(&a.v.heads(), LogKind::Member)
        .into_iter()
        .cloned()
        .collect();
    let kem = a.a.keys().kem_key();
    a.v.transact(|w| w.apply(kem, frames), |_, _| Ok::<_, Error>(()))
        .unwrap();
    assert!(
        !a.v.parked()
            .iter()
            .any(|r| matches!(r, ParkingReason::MutualRemoval { .. })),
        "{:?}",
        a.v.parked()
    );
    assert!(!a.v.is_member(&b.a.id()));
}
