use crate::v2::{FrameKind, LogKind, Pack};
use crate::vault::testing::{author, vault};
use crate::{Author, Error, Field, FieldType, Vault};

/// A checkpoint whose "sealed" bytes are the plaintext pack: core doesn't
/// care how the host lays it out, only that the frame commits to them.
fn checkpoint(v: &mut Vault, a: &Author) -> crate::Checkpointed {
    v.transact(
        |w| w.checkpoint(a, |pack, _| pack.encode().map_err(|e| e.to_string())),
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
    v.set_base(made.pack.clone());
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
    reopened.set_base(made.pack);
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
