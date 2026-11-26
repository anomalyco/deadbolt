//! Regressions from the security audit of the v2 cutover: reader duty,
//! void epochs, parking, stolen devices, equivocation and lent KEM keys.

use std::collections::BTreeSet;

use super::{Peer, first, login, pair, sync};
use crate::v2::{EpochKeyring, FrameId, FrameKind, LogKind, WriteEpochDecision};
use crate::vault::testing::author;
use crate::{Author, Error, Vault, VaultWrite};

/// Runs one change as `p`, committing nowhere.
fn tx<T>(
    p: &mut Peer,
    change: impl FnOnce(&mut VaultWrite<'_>, &Author) -> Result<T, Error>,
) -> Result<T, Error> {
    let (a, v) = (&p.a, &mut p.v);
    v.transact(|w| change(w, a), |_, _| Ok(()))
}

/// A adds D while, offline, B removes C and rotates to e1. D is a member
/// but nothing wraps e1 to it, so it can't read or write until a member
/// holding e1 does its reader duty (rule E6).
#[test]
fn a_device_added_during_a_rotation_gets_the_key_by_reader_duty() {
    let mut a = first();
    let mut b = pair(&mut a, 2);
    let mut c = pair(&mut a, 3);
    sync(&a, &mut b);
    sync(&a, &mut c);
    let mut d = pair(&mut a, 4);
    let cid = c.a.id();
    tx(&mut b, |w, x| w.remove(x, cid)).unwrap();
    let (secret, _) =
        b.v.create_item(&b.a, "login", None, login("b", "under e1"))
            .unwrap();
    sync(&b, &mut a);
    sync(&a, &mut b);
    sync(&a, &mut d);
    sync(&b, &mut d);
    assert!(d.v.is_member(&d.a.id()));
    assert!(d.v.item(&secret).is_none());
    assert!(matches!(
        d.v.create_item(&d.a, "login", None, login("d", "x")),
        Err(Error::AwaitingKeys)
    ));
    let made = tx(&mut b, |w, x| w.fulfill_reader_duty(x)).unwrap();
    assert_eq!(made.len(), 1, "one rewrap of e1 to D");
    assert!(
        tx(&mut b, |w, x| w.fulfill_reader_duty(x))
            .unwrap()
            .is_empty(),
        "nothing more is owed"
    );
    sync(&b, &mut d);
    assert_eq!(
        d.v.item(&secret).unwrap().fields["password"].value,
        "under e1"
    );
    let (mine, _) =
        d.v.create_item(&d.a, "login", None, login("d", "x"))
            .unwrap();
    sync(&d, &mut b);
    assert!(b.v.item(&mine).is_some());
}

/// A senior device's removal and a junior's concurrent removal of it: the
/// junior's loses, and its rotation, e_lose, never counts.
fn losing_epoch() -> (Peer, Peer, FrameId) {
    let mut a = first();
    let mut e = pair(&mut a, 2);
    let mut c = pair(&mut a, 3);
    sync(&a, &mut e);
    sync(&a, &mut c);
    let (aid, cid) = (a.a.id(), c.a.id());
    tx(&mut a, |w, x| w.remove(x, cid)).unwrap();
    let lose = tx(&mut e, |w, x| w.remove(x, aid)).unwrap();
    let (lost, _) =
        e.v.create_item(&e.a, "login", None, login("e", "lost"))
            .unwrap();
    sync(&a, &mut e);
    sync(&e, &mut a);
    assert!(a.v.is_member(&aid) && e.v.is_member(&e.a.id()));
    assert!(a.v.item(&lost).is_none() && e.v.item(&lost).is_none());
    (a, e, lose)
}

/// E writes E:0 under e_lose, which A can't open, then E:1 under the
/// winning epoch. A folds E:1 exactly as E does instead of waiting on E:0.
#[test]
fn a_frame_under_a_losing_epoch_doesnt_stall_its_authors_later_frames() {
    let (mut a, mut e, _) = losing_epoch();
    let aid = a.a.id();
    e.v.confirm_reinstated(&aid);
    let (kept, _) =
        e.v.create_item(&e.a, "login", None, login("e", "kept"))
            .unwrap();
    sync(&e, &mut a);
    assert_eq!(a.v.item(&kept).unwrap().fields["password"].value, "kept");
    assert_eq!(a.v.items(), e.v.items());
    assert_eq!(a.v.items().len(), 1, "nothing under e_lose counts anywhere");
}

/// A rotation minted while the clean tip's wrap to this device is junk
/// names only authorized parents, never the losing epoch this device holds.
#[test]
fn a_new_rotation_never_names_a_losing_epoch() {
    let (_, e, lose) = losing_epoch();
    let (graph, resolved, ring) = e.v.epoch_parts();
    let lose = crate::v2::EpochId::from_frame_id(lose);
    assert!(ring.contains(&lose) && !graph.get(&lose).unwrap().authorized);
    let tips = graph.clean_tips(resolved);
    let [win] = tips.as_slice() else {
        panic!("one clean tip: {tips:?}")
    };
    let mut partial = EpochKeyring::new();
    for id in ring.epoch_ids().into_iter().filter(|id| id != win) {
        partial.insert(id, ring.get(&id).unwrap().clone());
    }
    match graph.select_write_epoch(resolved, &partial, &BTreeSet::from([*win])) {
        WriteEpochDecision::MintRotate { parents } => {
            assert!(!parents.contains(&lose), "{parents:?}");
            assert!(parents.contains(win));
        }
        other => panic!("expected a rotation, got {other:?}"),
    }
}

/// A parked device refuses to write, even though it holds the epoch it
/// wrote under before: nothing new is sealed where a contested device may
/// read it.
#[test]
fn a_parked_device_refuses_to_write() {
    let mut a = first();
    let mut b = pair(&mut a, 2);
    let mut c = pair(&mut a, 3);
    sync(&a, &mut b);
    sync(&a, &mut c);
    a.v.create_item(&a.a, "login", None, login("a", "before"))
        .unwrap();
    let (bid, cid) = (b.a.id(), c.a.id());
    tx(&mut b, |w, x| w.remove(x, cid)).unwrap();
    tx(&mut c, |w, x| w.remove(x, bid)).unwrap();
    sync(&b, &mut a);
    sync(&c, &mut a);
    assert!(!a.v.parked().is_empty());
    let held = a.v.frames().count();
    assert!(matches!(
        a.v.create_item(&a.a, "login", None, login("a", "after")),
        Err(Error::Parked(_))
    ));
    assert_eq!(a.v.frames().count(), held);
}

/// The thief, holding S, adds its own device and removes B. Removing S as
/// stolen leaves the thief's device out of the new key and brings B back
/// into it, though A had received both frames.
#[test]
fn removing_a_stolen_device_cuts_its_additions_and_restores_its_victims() {
    let mut a = first();
    let mut s = pair(&mut a, 2);
    let mut b = pair(&mut a, 3);
    sync(&a, &mut s);
    sync(&a, &mut b);
    let mut attacker = pair(&mut s, 9);
    let (bid, sid, xid) = (b.a.id(), s.a.id(), attacker.a.id());
    tx(&mut s, |w, x| w.remove(x, bid)).unwrap();
    sync(&s, &mut a);
    assert!(a.v.is_member(&xid) && !a.v.is_member(&bid));
    tx(&mut a, |w, x| {
        w.remove_stolen(x.keys().sign_key(), sid, None)
    })
    .unwrap();
    assert!(!a.v.is_member(&sid));
    assert!(!a.v.is_member(&xid), "the thief's device is out");
    assert!(a.v.is_member(&bid), "the thief's removal of B is undone");
    assert!(a.v.parked().is_empty());
    let (id, _) =
        a.v.create_item(&a.a, "login", None, login("after", "theft"))
            .unwrap();
    assert!(
        tx(&mut a, |w, x| w.fulfill_reader_duty(x))
            .unwrap()
            .is_empty()
    );
    sync(&a, &mut b);
    assert_eq!(b.v.item(&id).unwrap().fields["password"].value, "theft");
    sync(&a, &mut attacker);
    assert!(attacker.v.item(&id).is_none());
    let fresh = Vault::open(attacker.a.keys(), a.v.frames().cloned()).unwrap();
    assert!(
        fresh.item(&id).is_none(),
        "no wrap reaches the thief's device"
    );
}

/// A signs two different data frames at one seq. X holds one, Y the other,
/// at the same count: their heads now differ by tip, so each sends the
/// stream, both see the fork and fold alike.
#[test]
fn equal_counts_with_different_tips_exchange_the_fork() {
    let mut a = first();
    let mut x = pair(&mut a, 2);
    let mut y = pair(&mut a, 3);
    sync(&a, &mut x);
    sync(&a, &mut y);
    let mut twin = Peer {
        a: author(1),
        v: a.v.clone(),
    };
    a.v.create_item(&a.a, "login", Some("one".into()), login("a", "1"))
        .unwrap();
    twin.v
        .create_item(&twin.a, "login", Some("two".into()), login("a", "2"))
        .unwrap();
    sync(&a, &mut x);
    sync(&twin, &mut y);
    let aid = a.a.id();
    let (hx, hy) = (x.v.heads(), y.v.heads());
    assert_eq!(hx.get(LogKind::Data, &aid), hy.get(LogKind::Data, &aid));
    assert_ne!(hx.tip(LogKind::Data, &aid), hy.tip(LogKind::Data, &aid));
    sync(&x, &mut y);
    sync(&y, &mut x);
    for p in [&x, &y] {
        assert!(p.v.membership().data_fork_seq.contains_key(&aid));
    }
    assert_eq!(x.v.items(), y.v.items());
}

/// S signs two membership frames at one seq. A member frame A writes after
/// seeing both names neither: honest frames never build on a void fork.
#[test]
fn a_member_frame_never_builds_on_a_voided_fork() {
    let mut a = first();
    let mut s = pair(&mut a, 2);
    let x = pair(&mut a, 3);
    let y = pair(&mut a, 4);
    sync(&a, &mut s);
    let mut twin = Peer {
        a: author(2),
        v: s.v.clone(),
    };
    let one = tx(&mut s, |w, au| w.remove(au, x.a.id())).unwrap();
    let two = tx(&mut twin, |w, au| w.remove(au, y.a.id())).unwrap();
    sync(&s, &mut a);
    sync(&twin, &mut a);
    assert!(a.v.membership().member_fork_seq.contains_key(&s.a.id()));
    a.v.confirm_reinstated(&x.a.id());
    a.v.confirm_reinstated(&y.a.id());
    let _d = pair(&mut a, 5);
    let newest =
        a.v.frames()
            .filter(|f| f.header().kind == FrameKind::Member && f.header().author == a.a.id())
            .max_by_key(|f| f.header().seq)
            .unwrap();
    let deps = &newest.member_body().unwrap().deps;
    assert!(!deps.contains(&one) && !deps.contains(&two), "{deps:?}");
}

/// The vault holds no KEM secret: a peer's rotation opens with the key lent
/// to `apply`, and a write rolled back keeps every key it held.
#[test]
fn applying_borrows_the_kem_key_and_a_rollback_keeps_the_keys() {
    let mut a = first();
    let mut b = pair(&mut a, 2);
    let mut c = pair(&mut a, 3);
    sync(&a, &mut b);
    sync(&a, &mut c);
    let cid = c.a.id();
    tx(&mut a, |w, x| w.remove(x, cid)).unwrap();
    let (id, _) =
        a.v.create_item(&a.a, "login", None, login("a", "new epoch"))
            .unwrap();
    sync(&a, &mut b);
    assert!(b.v.item(&id).is_some());
    let ba = &b.a;
    let failed: Result<FrameId, Error> =
        b.v.transact(|w| w.rename(ba, "lost"), |_, _| Err(Error::InvalidName));
    assert!(failed.is_err());
    assert!(b.v.item(&id).is_some());
    b.v.create_item(&b.a, "login", None, login("b", "still writes"))
        .unwrap();
}
