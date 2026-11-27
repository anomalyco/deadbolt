use std::collections::BTreeMap;

use crate::v2::{DataBody, FrameId, FrameKind, LogKind, Pack};
use crate::vault::testing::{author, vault};
use crate::{Author, Error, Field, FieldType, Vault};

/// A checkpoint whose "sealed" bytes are the plaintext pack: core doesn't
/// care how the host lays it out, only that the frame commits to them.
fn checkpoint(v: &mut Vault, a: &Author) -> crate::Checkpointed {
    v.transact(
        |w| {
            w.checkpoint(a, |pack, _| {
                let records = pack.split().map_err(|e| e.to_string())?;
                let joined = Pack::join(
                    &records.meta,
                    records.items.iter().map(|i| (&i.head[..], &i.secret[..])),
                )
                .map_err(|e| e.to_string())?;
                assert_eq!(&joined, pack);
                let mut bytes = records.meta.to_vec();
                for item in records.items {
                    bytes.extend_from_slice(&item.head);
                    bytes.extend_from_slice(&item.secret);
                }
                Ok(bytes)
            })
        },
        |_, _| Ok::<_, Error>(()),
    )
    .unwrap()
}

fn fill(v: &mut Vault, a: &Author, n: usize) {
    for i in 0..n {
        let fields = vec![
            (
                "username".into(),
                Field::new(FieldType::Text, format!("u{i}")),
            ),
            (
                "password".into(),
                Field::new(FieldType::Secret, format!("p{i}")),
            ),
            (
                "totp".into(),
                Field::new(FieldType::Otp, "JBSWY3DPEHPK3PXP"),
            ),
            (
                "url".into(),
                Field::new(FieldType::Url, format!("https://s{i}.com")),
            ),
        ];
        v.create_item(a, "login", Some(format!("Site {i}")), fields)
            .unwrap();
    }
}

#[test]
fn a_pack_splits_into_records_and_joins_back_bit_for_bit() {
    let a = author(1);
    let (mut v, _) = vault(&a, "personal");
    fill(&mut v, &a, 12);
    let made = checkpoint(&mut v, &a);
    let records = made.pack.split().unwrap();
    assert_eq!(records.items.len(), 12);
    let joined = Pack::join(
        &records.meta,
        records.items.iter().map(|i| (&i.head[..], &i.secret[..])),
    )
    .unwrap();
    assert_eq!(joined, made.pack);
    // The password and TOTP live in the Secret, named in the Head.
    let head = crate::v2::pack::ItemHead::decode(&records.items[0].head).unwrap();
    assert!(head.fields.contains_key("username") && !head.fields.contains_key("password"));
    assert_eq!(head.secret_fields["totp"], "otp");
    let secret = crate::v2::pack::ItemSecret::decode(&records.items[0].secret).unwrap();
    assert!(secret.value("password").is_some());
    // A Head with another item's Secret is refused.
    let swapped = [(&records.items[0].head[..], &records.items[1].secret[..])];
    assert!(Pack::join(&records.meta, swapped).is_err());
}

#[test]
fn a_vault_folds_from_its_checkpoint_to_the_same_items() {
    let a = author(1);
    let (mut v, _) = vault(&a, "personal");
    fill(&mut v, &a, 8);
    let made = checkpoint(&mut v, &a);
    assert!(v.pack_matches(&made.frame, &made.pack, &made.sealed));
    let frame = v.frame(&made.frame).unwrap();
    assert_eq!(frame.header().kind, FrameKind::Checkpoint);
    fill(&mut v, &a, 3);
    let before = v.items();
    v.set_base(made.frame, made.pack.clone());
    assert_eq!(v.items(), before);
    assert_eq!(v.tail_size().0, 4, "the checkpoint frame and three writes");

    // Reopened with only the frames above the frontier and the pack.
    let tail: Vec<_> = v
        .frames()
        .filter(|f| {
            f.header().kind.log_kind() == LogKind::Member
                || made
                    .pack
                    .meta
                    .frontier
                    .get(&f.header().author)
                    .is_none_or(|(seq, _)| f.header().seq > *seq)
        })
        .cloned()
        .collect();
    let mut reopened = Vault::open(a.keys(), tail).unwrap();
    assert!(reopened.adopt_base(made.frame, made.pack, &made.sealed));
    assert_eq!(reopened.items(), before);
    assert_eq!(reopened.name(), "personal");
}

#[test]
fn another_devices_honest_checkpoint_is_not_disputed() {
    let a = author(1);
    let (mut v, _) = vault(&a, "personal");
    let b = author(2);
    let consent = b.join_consent(&v.id(), &a.id());
    v.transact(
        |w| {
            w.add(&a, b.id(), b.keys().kem_public(), consent)?;
            w.card(&a, b.id(), b.keys().net_public(), "b")
        },
        |_, _| Ok::<_, Error>(()),
    )
    .unwrap();
    fill(&mut v, &a, 3);
    let mut vb = Vault::open(b.keys(), v.frames().cloned()).unwrap();
    checkpoint(&mut vb, &b);
    let frames: Vec<_> = vb.frames().cloned().collect();
    let kem = a.keys().kem_key();
    let disputed = v
        .transact(
            |w| {
                w.apply(kem, frames)?;
                w.judge_checkpoints(&a)
            },
            |_, _| Ok::<_, Error>(()),
        )
        .unwrap();
    assert_eq!(disputed, 0);
    assert_eq!(v.checkpoints().count(), 1);
}

/// `a` and a second device `b` sharing one vault, each with its copy.
fn two() -> (Author, Vault, Author, Vault) {
    let a = author(1);
    let (mut v, _) = vault(&a, "personal");
    let b = author(2);
    let consent = b.join_consent(&v.id(), &a.id());
    v.transact(
        |w| w.add(&a, b.id(), b.keys().kem_public(), consent),
        |_, _| Ok::<_, Error>(()),
    )
    .unwrap();
    let vb = Vault::open(b.keys(), v.frames().cloned()).unwrap();
    (a, v, b, vb)
}

fn give(from: &Vault, to: &mut Vault, kem: &crate::v2::KemSecret) {
    let frames: Vec<_> = from.frames().cloned().collect();
    to.transact(|w| w.apply(kem, frames), |_, _| Ok::<_, Error>(()))
        .unwrap();
}

#[test]
fn a_removed_devices_later_checkpoint_does_not_count() {
    let (a, mut v, b, mut vb) = two();
    fill(&mut vb, &b, 3);
    give(&vb, &mut v, a.keys().kem_key());
    v.transact(|w| w.remove(&a, b.id()), |_, _| Ok::<_, Error>(()))
        .unwrap();
    // b, not yet knowing, checkpoints what it holds.
    let made = checkpoint(&mut vb, &b);
    give(&vb, &mut v, a.keys().kem_key());
    assert!(v.frame(&made.frame).is_none() || v.checkpoints().all(|(f, _)| f.id != made.frame));
    assert!(!v.adopt_base(made.frame, made.pack, &made.sealed));
}

#[test]
fn a_frontier_past_this_devices_own_tip_contradicts_it() {
    let a = author(1);
    let (mut v, _) = vault(&a, "personal");
    fill(&mut v, &a, 2);
    let (tip, id) = v
        .frames()
        .filter(|f| f.header().author == a.id() && f.header().kind.log_kind() == LogKind::Data)
        .map(|f| (f.header().seq, f.id()))
        .max()
        .unwrap();
    let at = |seq, id| BTreeMap::from([(a.id(), (seq, id))]);
    assert!(!v.contradicts(&at(tip, id)));
    assert!(v.contradicts(&at(tip + 5, FrameId::ZERO)));
    assert!(v.contradicts(&at(tip, FrameId::ZERO)));
    // Another author's claim is the fold's to judge, not this check's.
    assert!(!v.contradicts(&BTreeMap::from([(author(7).id(), (9, FrameId::ZERO))])));
}

#[test]
fn a_judge_disputes_a_checkpoint_naming_its_own_frames_it_never_wrote() {
    let (a, mut v, b, mut vb) = two();
    fill(&mut v, &a, 2);
    give(&v, &mut vb, b.keys().kem_key());
    // a loses its last write (restored from an older copy) before judging.
    let mut older = Vault::open(
        a.keys(),
        v.frames()
            .filter(|f| {
                let h = f.header();
                !(h.author == a.id() && h.kind.log_kind() == LogKind::Data && h.seq >= 1)
            })
            .cloned(),
    )
    .unwrap();
    let made = checkpoint(&mut vb, &b);
    // Only b's own frames: none of a's that older lost.
    let frames: Vec<_> = vb
        .frames()
        .filter(|f| f.header().author == b.id())
        .cloned()
        .collect();
    let kem = a.keys().kem_key();
    let disputed = older
        .transact(
            |w| {
                w.apply(kem, frames)?;
                w.judge_checkpoints(&a)
            },
            |_, _| Ok::<_, Error>(()),
        )
        .unwrap();
    assert_eq!(disputed, 1);
    assert!(older.is_disputed(&made.frame));
    assert!(!older.adopt_base(made.frame, made.pack, &made.sealed));
}

#[test]
fn a_base_whose_checkpoint_is_disputed_is_dropped() {
    let (a, mut v, b, mut vb) = two();
    fill(&mut v, &a, 3);
    give(&v, &mut vb, b.keys().kem_key());
    let made = checkpoint(&mut vb, &b);
    assert!(vb.base().is_none() || vb.base_checkpoint() == Some(made.frame));
    vb.set_base(made.frame, made.pack.clone());
    assert_eq!(vb.base_checkpoint(), Some(made.frame));
    // a disputes it (whatever its reason) and b learns of the dispute.
    give(&vb, &mut v, a.keys().kem_key());
    let dispute = crate::v2::DataOp::Dispute {
        checkpoint: made.frame,
        expected_state_mac: [0; 32],
    };
    v.transact(|w| w.seal(&a, vec![dispute]), |_, _| Ok::<_, Error>(()))
        .unwrap();
    give(&v, &mut vb, b.keys().kem_key());
    assert!(vb.is_disputed(&made.frame));
    assert!(vb.base().is_none());
    assert_eq!(vb.base_checkpoint(), None);
}

/// A device that has only the base and the tail (the store collected the
/// rest, or it recovered from it) writes with a real clock: its edit and
/// delete of an item written below the frontier supersede it, with no
/// concurrent write left standing, whichever device id sorts first.
#[test]
fn a_device_folded_from_a_base_supersedes_what_the_base_covers() {
    let a = author(1);
    let mut lower = None;
    let mut higher = None;
    for seed in 2..64u8 {
        let d = author(seed);
        if d.id() < a.id() {
            lower.get_or_insert(d);
        } else {
            higher.get_or_insert(d);
        }
    }
    for d in [lower.unwrap(), higher.unwrap()] {
        supersedes_from_base(&a, &d);
    }
}

fn supersedes_from_base(a: &Author, d: &Author) {
    use crate::ops::{Change, DataOp};
    let (mut v, _) = vault(a, "personal");
    let consent = d.join_consent(&v.id(), &a.id());
    v.transact(
        |w| w.add(a, d.id(), d.keys().kem_public(), consent),
        |_, _| Ok::<_, Error>(()),
    )
    .unwrap();
    fill(&mut v, a, 3);
    let ids: Vec<_> = v.items().into_iter().map(|i| i.id).collect();
    let (edited, deleted) = (ids[0], ids[1]);
    // a edits once more, still below the frontier.
    let set = |value: &str| DataOp::Edit {
        item: edited,
        change: Change::Set {
            field: "password".into(),
            value: Field::new(FieldType::Secret, value),
        },
    };
    v.write(a, vec![set("from-a")]).unwrap();
    let made = checkpoint(&mut v, a);
    let frontier = made.pack.meta.frontier.clone();
    let tail: Vec<_> = v
        .frames()
        .filter(|f| {
            let h = f.header();
            h.kind.log_kind() == LogKind::Member
                || frontier.get(&h.author).is_none_or(|(seq, _)| h.seq > *seq)
        })
        .cloned()
        .collect();
    let mut vd = Vault::open(d.keys(), tail).unwrap();
    assert!(vd.adopt_base(made.frame, made.pack, &made.sealed));
    let edit = vd.write(d, vec![set("from-d")]).unwrap();
    let delete = DataOp::Edit {
        item: deleted,
        change: Change::Delete { at: None },
    };
    let gone = vd.write(d, vec![delete]).unwrap();
    // The first write names what it saw (the next only what's new since).
    let DataBody::Data(p) = &vd.opened[&edit].body else {
        panic!("not data");
    };
    assert!(!p.dclock.entries().is_empty(), "the write saw a's frames");
    assert!(vd.opened.contains_key(&gone));
    // a, holding everything, takes d's writes: each supersedes a's.
    give(&vd, &mut v, a.keys().kem_key());
    for w in [&v, &vd] {
        let writes = w.state.items[&edited].fields["password"].writes();
        assert_eq!(writes.len(), 1, "no concurrent password left standing");
        assert_eq!(
            writes[0].value.as_ref().map(|f| f.value.as_str()),
            Some("from-d")
        );
        assert!(w.state.items[&deleted].deleted());
        assert_eq!(w.state.items[&deleted].life.writes().len(), 1);
    }
    // d's clock, as a member's ack, covers a's frames below the frontier.
    let clocks = v.member_clocks();
    let (seq, _) = frontier[&a.id()];
    assert!(clocks[&d.id()].get(&a.id()) > seq);
}

#[test]
fn checkpoint_authenticates_metadata_even_when_state_and_sealed_bytes_match() {
    let a = author(1);
    let b = author(2);
    let (mut v, _) = vault(&a, "personal");
    let consent = b.join_consent(&v.id(), &a.id());
    v.transact(
        |w| w.add(&a, b.id(), b.keys().kem_public(), consent),
        |_, _| Ok::<_, Error>(()),
    )
    .unwrap();
    fill(&mut v, &a, 2);
    let mut vb = Vault::open(b.keys(), v.frames().cloned()).unwrap();
    fill(&mut vb, &b, 1);
    give(&vb, &mut v, a.keys().kem_key());
    let made = checkpoint(&mut v, &a);
    let mut tampered = made.pack.clone();
    // Shrinking a cross-stream clock is still structurally valid, but changes its MAC.
    let b_seq = tampered.meta.frontier[&b.id()].0;
    tampered.meta.stream_clocks.insert(
        b.id(),
        crate::v2::VectorClock::from_counts([(b.id(), b_seq + 1)]),
    );
    assert!(tampered.meta.validate(&tampered.state).is_ok());
    assert_ne!(tampered.meta, made.pack.meta);
    assert!(!v.pack_matches(&made.frame, &tampered, &made.sealed));
    assert_eq!(v.adopt_local_base(tampered), None);

    let mut inflated = made.pack.clone();
    inflated
        .meta
        .stream_clocks
        .get_mut(&b.id())
        .unwrap()
        .raise(a.id(), u64::MAX);
    assert!(inflated.meta.validate(&inflated.state).is_err());
    let seq = v.frame(&made.frame).unwrap().header().seq;
    // Even an unchecked foreign base must not vouch for a checkpoint above its frontier.
    v.set_base(made.frame, inflated);
    assert!(!v.acked(&b.id(), &a.id(), seq));
}

#[test]
fn maximum_frontier_is_rejected_and_removal_does_not_overflow() {
    let a = author(1);
    let b = author(2);
    let (mut v, _) = vault(&a, "personal");
    let consent = b.join_consent(&v.id(), &a.id());
    v.transact(
        |w| w.add(&a, b.id(), b.keys().kem_public(), consent),
        |_, _| Ok::<_, Error>(()),
    )
    .unwrap();
    let made = checkpoint(&mut v, &a);
    let mut bad = made.pack;
    bad.meta.frontier.insert(b.id(), (u64::MAX, FrameId::ZERO));
    bad.meta.stream_clocks.insert(
        b.id(),
        crate::v2::VectorClock::from_counts([(b.id(), u64::MAX)]),
    );
    assert!(bad.meta.validate(&bad.state).is_err());
    // Exercise the arithmetic defensively even if an internal caller bypasses validation.
    v.base = Some(bad);
    let result = v.transact(|w| w.remove(&a, b.id()), |_, _| Ok::<_, Error>(()));
    assert!(result.is_ok());
}
