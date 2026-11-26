//! The v2-backed vault: items, merges, membership, epochs and recovery.

use std::collections::BTreeSet;

use crate::v2::{Frame, LogKind, RecoverySecret};
use crate::vault::testing::{NOW_MS, author, recovery, vault};
use crate::{Author, DataOp, Error, Field, FieldType, Heads, ItemId, Vault};

fn login(user: &str, pw: &str) -> Vec<(String, Field)> {
    vec![
        ("username".into(), Field::new(FieldType::Text, user)),
        ("password".into(), Field::new(FieldType::Secret, pw)),
    ]
}

/// A peer: its author and its copy of the vault.
struct Peer {
    a: Author,
    v: Vault,
}

fn sync(from: &Peer, to: &mut Peer) {
    let heads = to.v.heads();
    let frames: Vec<Frame> = [LogKind::Member, LogKind::Data]
        .into_iter()
        .flat_map(|log| from.v.missing(&heads, log))
        .cloned()
        .collect();
    to.v.transact(|w| w.apply(frames), |_, _| Ok::<_, Error>(()))
        .unwrap();
}

/// `a` invites a new device seeded `seed`; the new device opens the vault
/// from everything `a` holds.
fn pair(a: &mut Peer, seed: u8) -> Peer {
    let b = author(seed);
    let consent = b.join_consent(&a.v.id(), &a.a.id());
    let (kem, net) = (b.keys().kem_public(), b.keys().net_public());
    let (aa, id) = (&a.a, b.id());
    a.v.transact(
        |w| {
            w.add(aa, id, kem, consent)?;
            w.card(aa, id, net, "laptop")
        },
        |_, _| Ok::<_, Error>(()),
    )
    .unwrap();
    let v = Vault::open(b.keys(), a.v.frames().cloned()).unwrap();
    Peer { a: b, v }
}

fn first() -> Peer {
    let a = author(1);
    let (v, frames) = vault(&a, "personal");
    assert_eq!(frames.len(), 3, "create, add, then the name and card");
    Peer { a, v }
}

#[test]
fn a_new_vault_has_its_name_one_member_and_a_recovery_root() {
    let p = first();
    assert_eq!(p.v.name(), "personal");
    assert_eq!(p.v.members().collect::<Vec<_>>(), vec![p.a.id()]);
    assert_eq!(p.v.recovery_root(), Some(recovery().recovery_id()));
    assert!(
        !p.v.is_member(&recovery().recovery_id()),
        "the root is not a device"
    );
    assert_eq!(p.v.device_card(&p.a.id()).unwrap().1, "test");
    let reopened = Vault::open(p.a.keys(), p.v.frames().cloned()).unwrap();
    assert_eq!(reopened.name(), "personal");
    assert!(Vault::create(&recovery(), &p.a, "Not Valid", "x").is_err());
}

#[test]
fn items_round_trip_with_every_kind_of_metadata() {
    let mut p = first();
    let (id, _) =
        p.v.create_item_with(
            &p.a,
            "login",
            Some("Mail".into()),
            login("me", "pw"),
            true,
            ["work/aws".into()],
        )
        .unwrap();
    let item = p.v.item(&id).unwrap();
    assert_eq!(item.name.as_deref(), Some("Mail"));
    assert!(item.favorite);
    assert_eq!(item.tags, BTreeSet::from(["work/aws".to_owned()]));
    assert_eq!(item.fields["password"].value, "pw");
    assert!(item.password_entry.is_some());
    let a = &p.a;
    p.v.write(
        a,
        vec![
            DataOp::favorite(id, false),
            DataOp::tag_remove(id, "WORK/AWS"),
            DataOp::name(id, None),
            DataOp::password_changed(id, Some("2026-01-02".into())),
            DataOp::ignore(id, "weak", Some(crate::Hash::from_bytes([7; 32]))),
            DataOp::remove(id, "username"),
        ],
    )
    .unwrap();
    let item = p.v.item(&id).unwrap();
    assert!(!item.favorite && item.tags.is_empty() && item.name.is_none());
    assert_eq!(item.password_changed.as_deref(), Some("2026-01-02"));
    assert_eq!(item.ignored["weak"], crate::Hash::from_bytes([7; 32]));
    assert!(!item.fields.contains_key("username"));
    p.v.write(a, vec![DataOp::delete(id, NOW_MS / 1000)])
        .unwrap();
    assert!(p.v.items().is_empty());
    assert_eq!(p.v.deleted()[0].at, Some(NOW_MS / 1000));
    p.v.write(a, vec![DataOp::restore(id)]).unwrap();
    assert_eq!(p.v.items().len(), 1);
}

#[test]
fn writes_are_checked_against_the_item_rules() {
    let mut p = first();
    let a = &p.a;
    assert!(matches!(
        p.v.create_item(a, "nope", None, []),
        Err(Error::Item(_))
    ));
    assert!(
        p.v.write(
            a,
            vec![DataOp::set(
                ItemId::random(),
                "password",
                Field::new(FieldType::Secret, "x")
            )]
        )
        .is_err()
    );
    let (id, _) = p.v.create_item(a, "login", None, login("u", "p")).unwrap();
    let too_many: Vec<DataOp> = (0..=crate::tag::MAX_TAGS)
        .map(|i| DataOp::tag_add(id, format!("t{i}")))
        .collect();
    assert!(p.v.write(a, too_many).is_err());
    // A failed write leaves no frame behind.
    let before = p.v.frames().count();
    assert!(
        p.v.write(a, vec![DataOp::name(id, Some("\u{0}".into()))])
            .is_err()
    );
    assert_eq!(p.v.frames().count(), before);
}

#[test]
fn paired_devices_converge_and_concurrent_edits_resolve() {
    let mut a = first();
    let (id, _) =
        a.v.create_item(&a.a, "login", None, login("me", "one"))
            .unwrap();
    let mut b = pair(&mut a, 2);
    assert!(b.v.is_member(&b.a.id()));
    assert_eq!(b.v.item(&id).unwrap().fields["password"].value, "one");
    // Concurrent: A edits, B deletes; then A tags, B untags the same tag.
    a.v.write(
        &a.a,
        vec![
            DataOp::set(id, "password", Field::new(FieldType::Secret, "two")),
            DataOp::tag_add(id, "x"),
        ],
    )
    .unwrap();
    b.v.write(
        &b.a,
        vec![DataOp::delete(id, 1), DataOp::tag_remove(id, "x")],
    )
    .unwrap();
    sync(&a, &mut b);
    sync(&b, &mut a);
    let (ia, ib) = (a.v.item(&id).unwrap(), b.v.item(&id).unwrap());
    assert_eq!(ia, ib);
    assert!(!ia.deleted, "a concurrent edit beats a delete");
    assert!(ia.tags.contains("x"), "a concurrent add beats a remove");
    assert_eq!(a.v.heads(), b.v.heads());
    assert_eq!(Heads::decode(&a.v.heads().encode()).unwrap(), a.v.heads());
}

#[test]
fn a_removed_device_cannot_read_what_is_written_after() {
    let mut a = first();
    let mut b = pair(&mut a, 2);
    let mut c = pair(&mut a, 3);
    sync(&a, &mut b);
    sync(&a, &mut c);
    let (aa, cid) = (&a.a, c.a.id());
    a.v.transact(|w| w.remove(aa, cid), |_, _| Ok::<_, Error>(()))
        .unwrap();
    let (secret, _) =
        a.v.create_item(&a.a, "login", None, login("after", "removal"))
            .unwrap();
    sync(&a, &mut c);
    sync(&a, &mut b);
    assert!(!c.v.is_member(&c.a.id()));
    assert!(
        c.v.item(&secret).is_none(),
        "the new epoch never wrapped to C"
    );
    assert!(c.v.sealed_count() > 0);
    assert_eq!(b.v.item(&secret).unwrap().fields["username"].value, "after");
    // C can't write any more.
    assert!(matches!(
        c.v.create_item(&c.a, "login", None, login("x", "y")),
        Err(Error::NotMember)
    ));
}

#[test]
fn concurrent_offline_removals_converge_on_one_write_epoch() {
    let mut a = first();
    let mut b = pair(&mut a, 2);
    let mut x = pair(&mut a, 3);
    let mut y = pair(&mut a, 4);
    for p in [&mut b, &mut x, &mut y] {
        sync(&a, p);
    }
    let (xa, xid, yid) = (&a.a, x.a.id(), y.a.id());
    a.v.transact(|w| w.remove(xa, xid), |_, _| Ok::<_, Error>(()))
        .unwrap();
    let ba = &b.a;
    b.v.transact(|w| w.remove(ba, yid), |_, _| Ok::<_, Error>(()))
        .unwrap();
    sync(&a, &mut b);
    sync(&b, &mut a);
    let (ia, _) =
        a.v.create_item(&a.a, "login", None, login("a", "1"))
            .unwrap();
    let (ib, _) =
        b.v.create_item(&b.a, "login", None, login("b", "2"))
            .unwrap();
    sync(&a, &mut b);
    sync(&b, &mut a);
    for p in [&a, &b] {
        assert!(p.v.item(&ia).is_some() && p.v.item(&ib).is_some());
        assert_eq!(p.v.members().count(), 2);
        assert!(p.v.parked().is_empty());
    }
    for p in [&mut x, &mut y] {
        sync(&a, p);
        assert!(p.v.item(&ia).is_none() && p.v.item(&ib).is_none());
    }
}

#[test]
fn the_recovery_kit_alone_recovers_everything_and_removes_lost_devices() {
    let mut a = first();
    let (id, _) =
        a.v.create_item(&a.a, "login", Some("Bank".into()), login("me", "hunter2"))
            .unwrap();
    let b = pair(&mut a, 2);
    let _ = b;
    // Every device is gone: only the frames (a remote) and the 24 words remain.
    let words = crate::recovery::encode(&recovery());
    let rs = crate::recovery::decode(&words).unwrap();
    let frames: Vec<Frame> = a.v.frames().cloned().collect();
    let mut as_root = Vault::open_as(rs.recovery_id(), &rs.kem_secret(), frames).unwrap();
    assert_eq!(
        as_root.item(&id).unwrap().fields["password"].value,
        "hunter2"
    );
    let new = author(9);
    let consent = new.join_consent(&as_root.id(), &rs.recovery_id());
    let old: Vec<_> = as_root.members().collect();
    as_root
        .transact(
            |w| {
                w.add_signed(
                    &rs.signing_key(),
                    new.id(),
                    new.keys().kem_public(),
                    consent,
                )?;
                for d in &old {
                    w.remove_by_root(&rs, *d)?;
                }
                Ok::<_, Error>(())
            },
            |_, _| Ok(()),
        )
        .unwrap();
    let mut fresh = Vault::open(new.keys(), as_root.frames().cloned()).unwrap();
    assert_eq!(fresh.members().collect::<Vec<_>>(), vec![new.id()]);
    assert_eq!(fresh.item(&id).unwrap().fields["password"].value, "hunter2");
    assert_eq!(fresh.name(), "personal");
    let (later, _) = fresh
        .create_item(&new, "login", None, login("new", "device"))
        .unwrap();
    // The old device sees it was removed and can't read the new write.
    sync(
        &Peer {
            a: author(9),
            v: fresh,
        },
        &mut a,
    );
    assert!(!a.v.is_member(&a.a.id()));
    assert!(a.v.item(&later).is_none());
}

#[test]
fn rotating_the_kit_retires_the_old_one() {
    let mut a = first();
    let old = recovery();
    let new = RecoverySecret::from_bytes([0x11; 32]);
    a.v.transact(|w| w.rotate_recovery(&old, &new), |_, _| Ok::<_, Error>(()))
        .unwrap();
    assert_eq!(a.v.recovery_root(), Some(new.recovery_id()));
    let (id, _) =
        a.v.create_item(&a.a, "login", None, login("u", "p"))
            .unwrap();
    let frames: Vec<Frame> = a.v.frames().cloned().collect();
    let as_new = Vault::open_as(new.recovery_id(), &new.kem_secret(), frames.clone()).unwrap();
    assert!(as_new.item(&id).is_some());
    let as_old = Vault::open_as(old.recovery_id(), &old.kem_secret(), frames).unwrap();
    assert!(
        as_old.item(&id).is_none(),
        "the old kit can't read past its rotation"
    );
    assert!(
        a.v.transact(|w| w.rotate_recovery(&old, &new), |_, _| Ok::<_, Error>(()))
            .is_err()
    );
}

#[test]
fn the_kit_undoes_a_stolen_senior_devices_removals() {
    let mut a = first();
    let mut b = pair(&mut a, 2);
    sync(&a, &mut b);
    // The thief holds the senior device A and removes B; B hears of it.
    let (aa, aid, bid) = (&a.a, a.a.id(), b.a.id());
    a.v.transact(|w| w.remove(aa, bid), |_, _| Ok::<_, Error>(()))
        .unwrap();
    sync(&a, &mut b);
    assert!(
        !b.v.is_member(&bid),
        "without the kit, seniority lets the thief win"
    );
    // With the kit, the root removes A citing only what came before the theft.
    let rs = recovery();
    b.v.transact(
        |w| w.remove_stolen(&rs.signing_key(), aid, None),
        |_, _| Ok::<_, Error>(()),
    )
    .unwrap();
    assert!(!b.v.is_member(&aid));
    assert!(b.v.is_member(&bid), "the thief's removal of B is void");
    assert!(b.v.parked().is_empty());
    let (id, _) =
        b.v.create_item(&b.a, "login", None, login("safe", "again"))
            .unwrap();
    sync(&b, &mut a);
    assert!(
        a.v.item(&id).is_none(),
        "the thief can't read B's new writes"
    );
}

#[test]
fn a_device_parks_when_a_device_it_saw_removed_comes_back() {
    let mut a = first();
    let mut b = pair(&mut a, 2);
    let mut c = pair(&mut a, 3);
    sync(&a, &mut b);
    sync(&a, &mut c);
    // B removes C, and C (senior to B? no: both added by A) removes B, offline.
    let (ba, cid, bid) = (&b.a, c.a.id(), b.a.id());
    b.v.transact(|w| w.remove(ba, cid), |_, _| Ok::<_, Error>(()))
        .unwrap();
    let ca = &c.a;
    c.v.transact(|w| w.remove(ca, bid), |_, _| Ok::<_, Error>(()))
        .unwrap();
    sync(&b, &mut a);
    sync(&c, &mut a);
    assert!(!a.v.parked().is_empty(), "mutual removals always park");
    assert!(matches!(
        a.v.create_item(&a.a, "login", None, login("x", "y")),
        Ok(_) | Err(Error::Parked(_))
    ));
}

/// A device holding a frame whose causal parent it lacks (a sync cut short)
/// can't fold that frame yet, so its own writes must not name it: they'd wait
/// on the same missing parent and vanish until it arrived.
#[test]
fn a_write_names_only_frames_the_fold_resolved() {
    let mut a = first();
    let mut b = pair(&mut a, 2);
    let mut c = pair(&mut a, 3);
    sync(&a, &mut b);
    let stage = |p: &mut Peer, name: &str| {
        let (pa, v) = (&p.a, &mut p.v);
        v.transact(
            |w| w.create_item(pa, "login", Some(name.into()), []),
            |_, _| Ok::<_, Error>(()),
        )
        .unwrap()
    };
    let (_, from_c) = stage(&mut c, "from c");
    sync(&c, &mut b);
    let (_, from_b) = stage(&mut b, "from b");
    // a gets b's write, which names c's, but not c's.
    let only = b.v.frame(&from_b).unwrap().clone();
    a.v.transact(|w| w.apply(vec![only]), |_, _| Ok::<_, Error>(()))
        .unwrap();
    assert!(a.v.frame(&from_c).is_none());
    assert!(
        a.v.items()
            .iter()
            .all(|i| i.name.as_deref() != Some("from b"))
    );
    let (mine, _) = stage(&mut a, "from a");
    assert!(a.v.item(&mine).is_some(), "a's own write counts at once");
    // Once c's frame arrives, everything folds.
    sync(&c, &mut a);
    assert_eq!(a.v.items().len(), 3);
}

/// Unlocking a large vault folds item shards in parallel; the result is the
/// one-pass fold's, edits, deletes, tags and all.
#[test]
fn a_parallel_fold_matches_a_sequential_one() {
    let mut a = first();
    let mut b = pair(&mut a, 2);
    let items: Vec<DataOp> = (0..1500)
        .map(|i| {
            DataOp::create(
                "login",
                Some(format!("site {i}")),
                login("me", &format!("pw{i}")),
            )
        })
        .collect();
    let (pa, v) = (&a.a, &mut a.v);
    let (ids, _) = v
        .transact(|w| w.create_items(pa, items), |_, _| Ok::<_, Error>(()))
        .unwrap();
    sync(&a, &mut b);
    let edits: Vec<DataOp> = ids
        .iter()
        .step_by(3)
        .map(|id| DataOp::set(*id, "password", Field::new(FieldType::Secret, "changed")))
        .collect();
    let (pb, v) = (&b.a, &mut b.v);
    v.transact(|w| w.write(pb, edits), |_, _| Ok::<_, Error>(()))
        .unwrap();
    let deletes: Vec<DataOp> = ids
        .iter()
        .step_by(7)
        .map(|id| DataOp::delete(*id, NOW_MS))
        .collect();
    let (pa, v) = (&a.a, &mut a.v);
    v.transact(|w| w.write(pa, deletes), |_, _| Ok::<_, Error>(()))
        .unwrap();
    sync(&a, &mut b);
    sync(&b, &mut a);
    let parallel = Vault::open(a.a.keys(), a.v.frames().cloned()).unwrap();
    crate::v2::fold::SEQUENTIAL.set(true);
    let sequential = Vault::open(a.a.keys(), a.v.frames().cloned()).unwrap();
    crate::v2::fold::SEQUENTIAL.set(false);
    assert_eq!(parallel.items(), sequential.items());
    assert_eq!(parallel.deleted(), sequential.deleted());
    assert_eq!(parallel.name(), sequential.name());
    assert_eq!(
        parallel.device_card(&b.a.id()),
        sequential.device_card(&b.a.id())
    );
    // A delete loses to the concurrent edit on every 21st item.
    let deleted = (0..1500).filter(|i| i % 7 == 0 && i % 3 != 0).count();
    assert_eq!(parallel.items().len(), 1500 - deleted);
}
