use crate::*;

struct Dev {
    secret: DeviceSecret,
    vault: Vault,
}

impl Dev {
    fn create() -> Self {
        let secret = DeviceSecret::generate();
        let (vault, _) = Vault::create(&secret, "personal").unwrap();
        Self { secret, vault }
    }

    fn id(&self) -> DeviceId {
        self.secret.device_id()
    }

    /// Adds a fresh device and hands it a copy of this vault.
    fn invite(&mut self) -> Dev {
        self.invite_with_entry().0
    }

    fn invite_with_entry(&mut self) -> (Dev, Entry) {
        let secret = DeviceSecret::generate();
        let consent = secret.join_consent(&self.vault.id(), &self.secret.device_id());
        let add = self
            .vault
            .add(&self.secret, secret.device_id(), consent)
            .unwrap();
        let vault = Vault::load(self.vault.entries().into_iter().cloned()).unwrap();
        (Dev { secret, vault }, add)
    }

    /// Sets a login field, typed per the login schema (extra fields: text).
    fn set(&mut self, item: ItemId, field: &str, value: &str) -> Entry {
        self.write(vec![DataOp::set(item, field, login_field(field, value))])
    }

    fn write(&mut self, ops: Vec<DataOp>) -> Entry {
        self.vault.write(&self.secret, ops).unwrap()
    }

    fn login_entry(&mut self, password: &str) -> (ItemId, Entry) {
        let fields = [("password".into(), secret(password))];
        self.vault
            .create_item(&self.secret, "login", None, fields)
            .unwrap()
    }

    fn login(&mut self, password: &str) -> ItemId {
        self.login_entry(password).0
    }

    /// Signs `ops` as this device's next data entry, based on everything it
    /// holds, without the commit-time checks, and applies it.
    fn raw(&mut self, ops: Vec<DataOp>) -> Entry {
        let log = LogId {
            author: self.id(),
            log: Log::Data,
        };
        let seq = self.vault.heads().get(&log).map_or(0, |seq| seq + 1);
        let deps: Vec<Hash> = self.vault.entries().iter().map(|e| e.hash()).collect();
        let entry = Entry::sign(&self.secret, self.vault.id(), seq, deps, Payload::Data(ops));
        assert_eq!(self.vault.apply(entry.clone()), Ok(true));
        entry
    }

    fn remove(&mut self, device: DeviceId) -> Entry {
        self.vault.remove(&self.secret, device).unwrap()
    }
}

fn text(value: &str) -> Field {
    Field::new(FieldType::Text, value)
}

fn secret(value: &str) -> Field {
    Field::new(FieldType::Secret, value)
}

fn login_field(name: &str, value: &str) -> Field {
    let kind = schema("login")
        .unwrap()
        .field(name)
        .map_or(FieldType::Text, |f| f.kind.clone());
    Field::new(kind, value)
}

fn value(item: &Item, field: &str) -> String {
    item.fields[field].value.clone()
}

fn sync(from: &Dev, to: &mut Dev) {
    for entry in from.vault.missing_for(&to.vault.heads()) {
        to.vault.apply(entry.clone()).unwrap();
    }
}

fn sync_both(a: &mut Dev, b: &mut Dev) {
    sync(a, b);
    sync(b, a);
}

/// Every entry known to any of `devs`, genesis first.
fn all_entries(devs: &[&Dev]) -> Vec<Entry> {
    let mut entries: Vec<Entry> = Vec::new();
    for dev in devs {
        for entry in dev.vault.entries() {
            if !entries.iter().any(|e| e.hash() == entry.hash()) {
                entries.push(entry.clone());
            }
        }
    }
    entries
}

/// Applies entries in the given order, retrying ones whose deps are not yet in.
fn apply_in_order(mut entries: Vec<Entry>) -> Vault {
    let genesis = entries.remove(0);
    let mut vault = Vault::from_genesis(genesis).unwrap();
    while !entries.is_empty() {
        let before = entries.len();
        entries.retain(|entry| match vault.apply(entry.clone()) {
            Ok(_) => false,
            Err(Error::MissingDeps(_) | Error::SeqGap { .. }) => true,
            Err(err) => panic!("unexpected {err}"),
        });
        assert!(entries.len() < before, "no progress");
    }
    vault
}

type Snapshot = (Vec<DeviceId>, Vec<Option<Item>>, Vec<Vec<Version>>);

fn snapshot(vault: &Vault, items: &[ItemId]) -> Snapshot {
    (
        vault.members().collect(),
        items.iter().map(|id| vault.item(id)).collect(),
        items.iter().map(|id| vault.history(id)).collect(),
    )
}

/// Membership ops at equal depth are replayed in hash order, which depends on
/// random keys. Runs `scenario` until it has reported both orders of the pair
/// it cares about (`true` if the first op sorts first).
fn both_orders(mut scenario: impl FnMut(bool) -> bool) {
    let mut seen = [false; 2];
    for run in 0..64 {
        seen[scenario(run == 0) as usize] = true;
        if seen == [true; 2] {
            return;
        }
    }
    panic!("only one replay order was exercised");
}

/// Applies `entries` in many causal orders and asserts every result matches.
fn assert_order_independent(entries: &[Entry], items: &[ItemId]) -> Vault {
    let (genesis, rest) = entries.split_first().unwrap();
    let mut orders: Vec<Vec<Entry>> = vec![rest.to_vec(), rest.iter().rev().cloned().collect()];
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..6 {
        let mut order = rest.to_vec();
        for i in (1..order.len()).rev() {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            order.swap(i, (seed >> 33) as usize % (i + 1));
        }
        orders.push(order);
    }
    let vaults: Vec<Vault> = orders
        .into_iter()
        .map(|order| apply_in_order([vec![genesis.clone()], order].concat()))
        .collect();
    let expected = snapshot(&vaults[0], items);
    for vault in &vaults[1..] {
        assert_eq!(snapshot(vault, items), expected);
    }
    vaults.into_iter().next().unwrap()
}

fn data_entry(secret: &DeviceSecret, vault: &Vault, seq: u64, deps: Vec<Hash>) -> Entry {
    let op = DataOp::set(ItemId::from_bytes([1; 16]), "f", text("v"));
    Entry::sign(secret, vault.id(), seq, deps, Payload::Data(vec![op]))
}

fn genesis_hash(vault: &Vault) -> Hash {
    vault.entries()[0].hash()
}

// ---- identity -------------------------------------------------------------

#[test]
fn device_secret_round_trips_and_redacts() {
    let secret = DeviceSecret::generate();
    let restored = DeviceSecret::from_bytes(&secret.to_bytes());
    assert_eq!(restored.device_id(), secret.device_id());
    let debug = format!("{secret:?}");
    assert!(!debug.contains(&Hash::from_bytes(*secret.to_bytes()).to_string()));
}

// ---- ingestion ------------------------------------------------------------

#[test]
fn rejects_tampered_entries() {
    let mut a = Dev::create();
    let (_, entry) = a.login_entry("hunter2");
    let mut fresh = Vault::from_genesis(a.vault.entries()[0].clone()).unwrap();

    let mut body = entry.encode();
    let at = body.windows(7).position(|w| w == b"hunter2").unwrap();
    body[at] = b'H';
    assert_eq!(
        fresh.apply(Entry::decode(&body).unwrap()),
        Err(Error::BadSignature)
    );

    let mut signature = entry.encode();
    let last = signature.len() - 1;
    signature[last] ^= 0x01;
    assert_eq!(
        fresh.apply(Entry::decode(&signature).unwrap()),
        Err(Error::BadSignature)
    );

    // Re-signed by someone else under the original author's name is impossible:
    // signing always uses the signer's own id.
    let forged = data_entry(
        &DeviceSecret::generate(),
        &fresh,
        0,
        vec![genesis_hash(&fresh)],
    );
    assert_ne!(forged.author(), a.id());

    assert_eq!(fresh.apply(entry.clone()), Ok(true));
    assert_eq!(fresh.apply(entry), Ok(false));
}

#[test]
fn rejects_tampered_genesis() {
    let secret = DeviceSecret::generate();
    let (_, genesis) = Vault::create(&secret, "personal").unwrap();
    let mut bytes = genesis.encode();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    assert_eq!(
        Vault::from_genesis(Entry::decode(&bytes).unwrap()).err(),
        Some(Error::BadSignature)
    );
    let fake = Entry::sign(
        &secret,
        genesis.vault(),
        0,
        [],
        Payload::Membership(MembershipOp::Create {
            device: secret.device_id(),
            nonce: [0; 32],
            name: "personal".into(),
        }),
    );
    assert_eq!(Vault::from_genesis(fake).err(), Some(Error::InvalidGenesis));
}

#[test]
fn rejects_seq_gaps_and_forks() {
    let mut a = Dev::create();
    let (item, e0) = a.login_entry("0");
    let e1 = a.set(item, "f", "1");
    let mut fresh = Vault::from_genesis(a.vault.entries()[0].clone()).unwrap();
    assert_eq!(
        fresh.apply(e1.clone()),
        Err(Error::SeqGap {
            expected: 0,
            got: 1
        })
    );
    fresh.apply(e0.clone()).unwrap();
    fresh.apply(e1).unwrap();
    let fork = data_entry(&a.secret, &fresh, 0, vec![genesis_hash(&fresh)]);
    assert_eq!(fresh.apply(fork), Err(Error::Fork { seq: 0 }));
}

#[test]
fn rejects_missing_deps() {
    let mut a = Dev::create();
    let mut b = a.invite();
    let mut c = Vault::load(a.vault.entries().into_iter().cloned()).unwrap();
    let (_, a0) = a.login_entry("a");
    sync(&a, &mut b);
    let (_, b0) = b.login_entry("b");
    assert_eq!(
        c.apply(b0.clone()),
        Err(Error::MissingDeps(vec![a0.hash()]))
    );
    c.apply(a0).unwrap();
    c.apply(b0).unwrap();
}

#[test]
fn requires_previous_entry_in_deps() {
    let mut a = Dev::create();
    a.login("0");
    let entry = data_entry(&a.secret, &a.vault, 1, vec![genesis_hash(&a.vault)]);
    assert_eq!(a.vault.apply(entry), Err(Error::InvalidDeps));
}

#[test]
fn membership_entries_cannot_depend_on_data() {
    let mut a = Dev::create();
    let (_, d0) = a.login_entry("0");
    let joiner = DeviceSecret::generate();
    let op = MembershipOp::Add {
        device: joiner.device_id(),
        consent: joiner.join_consent(&a.vault.id(), &a.id()),
    };
    let entry = Entry::sign(
        &a.secret,
        a.vault.id(),
        1,
        [genesis_hash(&a.vault), d0.hash()],
        Payload::Membership(op),
    );
    assert_eq!(a.vault.apply(entry), Err(Error::InvalidDeps));
}

#[test]
fn rejects_non_member_authors() {
    let mut a = Dev::create();
    let outsider = DeviceSecret::generate();
    let genesis = genesis_hash(&a.vault);

    let entry = data_entry(&outsider, &a.vault, 0, vec![genesis]);
    assert_eq!(a.vault.apply(entry), Err(Error::NotMember));

    let self_add = MembershipOp::Add {
        device: outsider.device_id(),
        consent: outsider.join_consent(&a.vault.id(), &outsider.device_id()),
    };
    let entry = Entry::sign(
        &outsider,
        a.vault.id(),
        0,
        [genesis],
        Payload::Membership(self_add),
    );
    assert_eq!(a.vault.apply(entry), Err(Error::NotMember));

    let op = DataOp::set(ItemId::random(), "f", text("v"));
    assert_eq!(a.vault.write(&outsider, vec![op]), Err(Error::NotMember));
    assert!(!a.vault.is_member(&outsider.device_id()));
}

#[test]
fn rejects_wrong_vault_bad_consent_and_second_genesis() {
    let mut a = Dev::create();
    let other = Dev::create();
    let entry = data_entry(&a.secret, &other.vault, 0, vec![genesis_hash(&other.vault)]);
    assert!(matches!(
        a.vault.apply(entry),
        Err(Error::WrongVault { .. })
    ));

    let joiner = DeviceSecret::generate();
    let wrong = joiner.join_consent(&other.vault.id(), &a.id());
    assert_eq!(
        a.vault.add(&a.secret, joiner.device_id(), wrong),
        Err(Error::InvalidConsent)
    );
    assert!(!a.vault.is_member(&joiner.device_id()));

    let create = MembershipOp::Create {
        device: a.id(),
        nonce: [3; 32],
        name: "personal".into(),
    };
    assert_eq!(
        a.vault.commit(&a.secret, Payload::Membership(create)),
        Err(Error::InvalidGenesis)
    );
}

// ---- is_member --------------------------------------------------------------

#[test]
fn is_member_creator_and_added_devices() {
    let mut a = Dev::create();
    assert!(a.vault.is_member(&a.id()));
    assert!(!a.vault.is_member(&DeviceSecret::generate().device_id()));
    let b = a.invite();
    for vault in [&a.vault, &b.vault] {
        assert!(vault.is_member(&a.id()));
        assert!(vault.is_member(&b.id()));
        assert_eq!(vault.members().count(), 2);
    }
}

#[test]
fn is_member_false_after_removal_everywhere() {
    let mut a = Dev::create();
    let mut b = a.invite();
    let mut c = a.invite();
    sync(&a, &mut b);
    a.remove(b.id());
    sync(&a, &mut b);
    sync(&a, &mut c);
    for vault in [&a.vault, &b.vault, &c.vault] {
        assert!(!vault.is_member(&b.id()));
        assert!(vault.is_member(&a.id()));
        assert!(vault.is_member(&c.id()));
    }
    let op = DataOp::set(ItemId::random(), "f", text("v"));
    assert_eq!(b.vault.write(&b.secret, vec![op]), Err(Error::NotMember));
    assert_eq!(b.vault.remove(&b.secret, a.id()), Err(Error::NotMember));
}

#[test]
fn is_member_removed_device_cannot_be_re_added() {
    let mut a = Dev::create();
    let mut b = a.invite();
    let mut c = a.invite();
    sync(&a, &mut b);
    a.remove(b.id());
    sync(&a, &mut c);
    assert!(a.vault.was_removed(&b.id()));
    assert!(c.vault.was_removed(&b.id()));

    assert_eq!(
        a.vault.add(
            &a.secret,
            b.id(),
            b.secret.join_consent(&a.vault.id(), &a.id()),
        ),
        Err(Error::AddRemovedDevice)
    );
    assert_eq!(
        c.vault.add(
            &c.secret,
            b.id(),
            b.secret.join_consent(&c.vault.id(), &c.id()),
        ),
        Err(Error::AddRemovedDevice)
    );
    assert!(!a.vault.is_member(&b.id()));
    assert!(!c.vault.is_member(&b.id()));

    // Concurrent with the removal: an add of an existing member changes nothing.
    let mut d = Dev::create();
    let mut e = d.invite();
    let mut f = d.invite();
    sync(&d, &mut e);
    d.remove(e.id());
    f.vault
        .add(
            &f.secret,
            e.id(),
            e.secret.join_consent(&d.vault.id(), &f.id()),
        )
        .unwrap();
    sync_both(&mut d, &mut f);
    assert!(!d.vault.is_member(&e.id()));
    assert!(!f.vault.is_member(&e.id()));
    assert!(d.vault.was_removed(&e.id()));
    assert!(f.vault.was_removed(&e.id()));
}

#[test]
fn is_member_excludes_devices_added_by_concurrently_removed_device() {
    both_orders(|permute| {
        let mut a = Dev::create();
        let mut b = a.invite();
        let (d, add_d) = b.invite_with_entry();
        let remove_b = a.remove(b.id());
        sync_both(&mut a, &mut b);
        for vault in [&a.vault, &b.vault] {
            assert!(!vault.is_member(&b.id()));
            assert!(!vault.is_member(&d.id()));
            assert!(vault.is_member(&a.id()));
        }
        if permute {
            assert_order_independent(&all_entries(&[&a, &b]), &[]);
        }
        add_d.hash() < remove_b.hash()
    });
}

#[test]
fn is_member_keeps_devices_added_before_removal() {
    let mut a = Dev::create();
    let mut b = a.invite();
    let d = b.invite();
    sync(&b, &mut a);
    a.remove(b.id());
    sync(&a, &mut b);
    for vault in [&a.vault, &b.vault] {
        assert!(!vault.is_member(&b.id()));
        assert!(vault.is_member(&d.id()));
    }
}

#[test]
fn is_member_concurrent_mutual_removal_earlier_added_wins() {
    both_orders(|permute| {
        let mut a = Dev::create();
        let mut b = a.invite();
        let remove_b = a.remove(b.id());
        let remove_a = b.remove(a.id());
        sync_both(&mut a, &mut b);
        for vault in [&a.vault, &b.vault] {
            assert!(vault.is_member(&a.id()));
            assert!(!vault.is_member(&b.id()));
        }
        if permute {
            let vault = assert_order_independent(&all_entries(&[&a, &b]), &[]);
            assert!(vault.is_member(&a.id()));
            assert!(!vault.is_member(&b.id()));
        }
        remove_b.hash() < remove_a.hash()
    });
}

#[test]
fn is_member_mutual_removal_between_non_creators() {
    both_orders(|permute| {
        let mut a = Dev::create();
        let mut b = a.invite();
        let mut c = a.invite();
        sync(&a, &mut b);
        let remove_b = c.remove(b.id());
        let remove_c = b.remove(c.id());
        sync_both(&mut b, &mut c);
        sync(&b, &mut a);
        for vault in [&a.vault, &b.vault, &c.vault] {
            assert!(vault.is_member(&a.id()));
            assert!(vault.is_member(&b.id()), "b was added before c");
            assert!(!vault.is_member(&c.id()));
        }
        if permute {
            assert_order_independent(&all_entries(&[&a, &b, &c]), &[]);
        }
        remove_b.hash() < remove_c.hash()
    });
}

#[test]
fn is_member_mutual_removal_winner_keeps_its_concurrent_ops() {
    // b wins the mutual removal, so its concurrent add of d must survive even
    // when c's losing removal of b is replayed first and cuts it.
    both_orders(|permute| {
        let mut a = Dev::create();
        let mut b = a.invite();
        let mut c = a.invite();
        sync(&a, &mut b);
        let (d, add_d) = b.invite_with_entry();
        b.remove(c.id());
        let remove_b = c.remove(b.id());
        sync_both(&mut b, &mut c);
        sync(&b, &mut a);
        for vault in [&a.vault, &b.vault, &c.vault] {
            assert!(vault.is_member(&b.id()));
            assert!(vault.is_member(&d.id()));
            assert!(!vault.is_member(&c.id()));
        }
        if permute {
            assert_order_independent(&all_entries(&[&a, &b, &c]), &[]);
        }
        add_d.hash() < remove_b.hash()
    });
}

#[test]
fn is_member_removal_seen_before_counter_removal_is_final() {
    // b saw its own removal and then tried to remove a: not concurrent, b loses.
    let mut a = Dev::create();
    let mut b = a.invite();
    let mut c = a.invite();
    sync(&a, &mut b);
    c.remove(b.id());
    sync(&c, &mut b);
    let rogue = Entry::sign(
        &b.secret,
        b.vault.id(),
        0,
        b.vault.entries().iter().map(|e| e.hash()),
        Payload::Membership(MembershipOp::Remove {
            device: a.id(),
            last_seen_seq: None,
        }),
    );
    assert_eq!(b.vault.apply(rogue), Err(Error::NotMember));
    sync(&b, &mut a);
    assert!(a.vault.is_member(&a.id()));
    assert!(!a.vault.is_member(&b.id()));
}

#[test]
fn is_member_self_removal() {
    let mut a = Dev::create();
    let mut b = a.invite();
    b.remove(b.id());
    sync(&b, &mut a);
    assert!(!a.vault.is_member(&b.id()));
    assert!(a.vault.is_member(&a.id()));
}

// ---- name -----------------------------------------------------------------

#[test]
fn rename_syncs_and_later_rename_wins() {
    let mut a = Dev::create();
    let mut b = a.invite();
    assert_eq!(b.vault.name(), "personal");
    a.vault.rename(&a.secret, "family").unwrap();
    sync(&a, &mut b);
    assert_eq!(b.vault.name(), "family");
    // Based on "family", so it wins regardless of hashes.
    for round in 0..4 {
        let name = format!("b{round}");
        b.vault.rename(&b.secret, name.as_str()).unwrap();
        sync(&b, &mut a);
        assert_eq!(a.vault.name(), name);
    }
    let reloaded = Vault::load(a.vault.entries().into_iter().cloned()).unwrap();
    assert_eq!(reloaded.name(), "b3");
}

#[test]
fn concurrent_renames_pick_hash_winner_in_any_order() {
    let mut a = Dev::create();
    let mut b = a.invite();
    let mut c = a.invite();
    sync(&a, &mut b);
    let renames = [
        a.vault.rename(&a.secret, "from-a").unwrap(),
        b.vault.rename(&b.secret, "from-b").unwrap(),
        c.vault.rename(&c.secret, "from-c").unwrap(),
    ];
    let winner = renames.iter().max_by_key(|e| e.hash()).unwrap();
    let Payload::Membership(MembershipOp::Rename { name }) = winner.payload() else {
        unreachable!()
    };
    let vault = assert_order_independent(&all_entries(&[&a, &b, &c]), &[]);
    assert_eq!(vault.name(), name);
    sync_both(&mut a, &mut b);
    sync_both(&mut a, &mut c);
    sync(&a, &mut b);
    for dev in [&a, &b, &c] {
        assert_eq!(dev.vault.name(), name);
    }
}

#[test]
fn rename_by_concurrently_removed_device_is_ignored() {
    let mut a = Dev::create();
    let mut b = a.invite();
    b.vault.rename(&b.secret, "hijacked").unwrap();
    a.remove(b.id());
    sync_both(&mut a, &mut b);
    assert_eq!(a.vault.name(), "personal");
    assert_eq!(b.vault.name(), "personal");
    assert_eq!(b.vault.rename(&b.secret, "again"), Err(Error::NotMember));
}

#[test]
fn invalid_names_are_rejected() {
    let secret = DeviceSecret::generate();
    for name in ["", "Personal", "9lives", "-x", "has space", &"x".repeat(65)] {
        assert_eq!(Vault::create(&secret, name).err(), Some(Error::InvalidName));
    }

    let mut a = Dev::create();
    assert_eq!(a.vault.rename(&a.secret, "Bad"), Err(Error::InvalidName));
    let bad = Payload::Membership(MembershipOp::Rename { name: "no!".into() });
    assert_eq!(
        a.vault.commit(&a.secret, bad.clone()),
        Err(Error::InvalidName)
    );
    let entry = Entry::sign(&a.secret, a.vault.id(), 1, [genesis_hash(&a.vault)], bad);
    assert_eq!(a.vault.apply(entry), Err(Error::InvalidName));
    assert_eq!(a.vault.name(), "personal");

    // A genesis that is valid apart from its name.
    let device = secret.device_id();
    let (_, good) = Vault::create(&secret, "ok").unwrap();
    let Payload::Membership(MembershipOp::Create { nonce, .. }) = good.payload() else {
        unreachable!()
    };
    let bad_genesis = Entry::sign(
        &secret,
        good.vault(),
        0,
        [],
        Payload::Membership(MembershipOp::Create {
            device,
            nonce: *nonce,
            name: "UPPER".into(),
        }),
    );
    assert_eq!(
        Vault::from_genesis(bad_genesis).err(),
        Some(Error::InvalidName)
    );
}

#[test]
fn one_device_key_across_vaults() {
    let mut a = Dev::create();
    let secret = a.invite().secret;
    let (mut work, _) = Vault::create(&secret, "work").unwrap();
    assert_ne!(work.id(), a.vault.id());
    // Consent for one vault cannot be reused in another.
    let joiner = DeviceSecret::generate();
    let consent = joiner.join_consent(&a.vault.id(), &secret.device_id());
    assert_eq!(
        work.add(&secret, joiner.device_id(), consent),
        Err(Error::InvalidConsent)
    );
    work.add(
        &secret,
        joiner.device_id(),
        joiner.join_consent(&work.id(), &secret.device_id()),
    )
    .unwrap();
    assert!(work.is_member(&joiner.device_id()));
    assert!(!a.vault.is_member(&joiner.device_id()));
    assert_eq!((a.vault.name(), work.name()), ("personal", "work"));
}

// ---- data -----------------------------------------------------------------

#[test]
fn items_set_delete_and_restore() {
    let mut a = Dev::create();
    let fields = [
        ("username".into(), text("dax")),
        ("password".into(), secret("one")),
    ];
    let (item, _) = a
        .vault
        .create_item(&a.secret, "login", None, fields)
        .unwrap();
    a.set(item, "password", "two");
    let got = a.vault.item(&item).unwrap();
    assert_eq!(got.kind, "login");
    assert_eq!(got.name, None);
    assert_eq!(got.fields["password"], secret("two"));
    assert_eq!(a.vault.items().len(), 1);

    a.write(vec![DataOp::remove(item, "username")]);
    assert!(!a.vault.item(&item).unwrap().fields.contains_key("username"));

    a.write(vec![DataOp::delete(item)]);
    assert!(a.vault.item(&item).unwrap().deleted);
    assert!(a.vault.items().is_empty());

    a.set(item, "notes", "back");
    let got = a.vault.item(&item).unwrap();
    assert!(!got.deleted);
    assert_eq!(value(&got, "password"), "two");
    assert_eq!(got.fields["notes"], Field::new(FieldType::Note, "back"));

    let statuses: Vec<VersionStatus> = a.vault.history(&item).iter().map(|v| v.status).collect();
    use VersionStatus::*;
    assert_eq!(
        statuses,
        [
            Superseded, Superseded, Current, Current, Superseded, Current
        ]
    );
}

#[test]
fn item_ids_derive_from_the_creating_op() {
    let mut a = Dev::create();
    let ops = vec![
        DataOp::create("login", None, [("password".into(), secret("1"))]),
        DataOp::create("login", None, [("password".into(), secret("2"))]),
    ];
    let entry = a.write(ops);
    let ids = [0, 1].map(|i| ItemId::of_create(&entry.hash(), i));
    assert_ne!(ids[0], ids[1]);
    assert_eq!(value(&a.vault.item(&ids[1]).unwrap(), "password"), "2");
}

#[test]
fn create_items_batches_entries_and_is_all_or_nothing() {
    let mut a = Dev::create();
    let big = "x".repeat(CREATE_BATCH_BYTES / 4);
    let login = |password: &str| {
        DataOp::create(
            "login",
            None,
            [
                ("password".to_string(), secret(password)),
                (
                    "notes".to_string(),
                    Field::new(FieldType::Note, big.clone()),
                ),
            ],
        )
    };
    let items: Vec<_> = (0..10).map(|i| login(&i.to_string())).collect();
    let (ids, entries) = a.vault.create_items(&a.secret, items).unwrap();
    assert_eq!(ids.len(), 10);
    assert!(
        (3..10).contains(&entries.len()),
        "{} entries",
        entries.len()
    );
    assert_eq!(value(&a.vault.item(&ids[9]).unwrap(), "password"), "9");
    assert_eq!(a.vault.items().len(), 10);

    let mut items: Vec<_> = (0..10).map(|i| login(&i.to_string())).collect();
    items.push(DataOp::create("card", None, []));
    assert_eq!(
        a.vault.create_items(&a.secret, items).unwrap_err(),
        Error::Item(ItemError::MissingField("number"))
    );
    assert_eq!(a.vault.items().len(), 10);
}

fn note(name: &str, len: usize) -> DataOp {
    DataOp::create(
        "note",
        Some(name.into()),
        [(
            "notes".into(),
            Field::new(FieldType::Secret, "n".repeat(len)),
        )],
    )
}

/// A realistic import (thousands of logins, a few large notes, one near the sync
/// limit) lands in entries that all fit a sync frame; the size check is exact.
#[test]
fn large_imports_split_into_syncable_entries() {
    let mut a = Dev::create();
    let mut items: Vec<_> = (0..5000)
        .map(|i| {
            DataOp::create(
                "login",
                Some(format!("Site {i}")),
                [
                    ("password".into(), secret(&format!("pw-{i:032}"))),
                    (
                        "username".into(),
                        Field::new(FieldType::Text, "me@example.com"),
                    ),
                    (
                        "url".into(),
                        Field::new(FieldType::Url, format!("https://{i}.example.com/login")),
                    ),
                    (
                        "notes".into(),
                        Field::new(FieldType::Note, "x".repeat(1 + i % 700)),
                    ),
                ],
            )
        })
        .collect();
    items.extend((0..4).map(|i| note(&format!("big {i}"), 3 * CREATE_BATCH_BYTES / 2)));
    items.push(note("huge", MAX_ENTRY_LEN - 1024));
    let total: usize = items.iter().map(DataOp::encoded_len).sum();
    let (ids, entries) = a.vault.create_items(&a.secret, items).unwrap();
    assert_eq!(ids.len(), 5005);
    assert_eq!(a.vault.items().len(), 5005);
    assert!(
        entries.len() <= total / CREATE_BATCH_BYTES + 6,
        "{}",
        entries.len()
    );
    for entry in &entries {
        let len = entry.encode().len();
        assert_eq!(entry.encoded_len(), len);
        let Payload::Data(ops) = entry.payload() else {
            unreachable!()
        };
        let ops_len = ops.iter().map(DataOp::encoded_len).sum();
        assert_eq!(entry::data_entry_len(entry.deps().len(), ops_len), len);
        assert!(len <= MAX_ENTRY_LEN);
        assert!(ops.len() == 1 || ops_len <= CREATE_BATCH_BYTES);
    }
}

/// An item too large to ever sync is refused before anything is written, in an
/// import or on its own, with an error that says so.
#[test]
fn entries_too_large_to_sync_are_refused() {
    let mut a = Dev::create();
    let heads = a.vault.heads();
    let items = vec![note("ok", 10), note("huge", MAX_ENTRY_LEN)];
    let error = a.vault.create_items(&a.secret, items).unwrap_err();
    assert!(
        matches!(error, Error::TooLarge { len, max } if len > max && max == MAX_ENTRY_LEN),
        "{error:?}"
    );
    assert!(error.to_string().contains("too large to sync"));
    assert_eq!(a.vault.heads(), heads);

    let error = a
        .vault
        .write(&a.secret, vec![note("huge", MAX_ENTRY_LEN)])
        .unwrap_err();
    assert!(matches!(error, Error::TooLarge { .. }), "{error:?}");
    // Many ops that are each fine but too large together are refused too.
    let ops = (0..3)
        .map(|i| note(&i.to_string(), MAX_ENTRY_LEN / 3))
        .collect();
    let error = a.vault.write(&a.secret, ops).unwrap_err();
    assert!(matches!(error, Error::TooLarge { .. }), "{error:?}");
    assert_eq!(a.vault.heads(), heads);
    assert!(a.vault.items().is_empty());

    // An edit is held to the same limit.
    let (id, _) = a
        .vault
        .create_item(&a.secret, "note", Some("small".into()), [])
        .unwrap();
    let edit = DataOp::set(
        id,
        "notes",
        Field::new(FieldType::Secret, "n".repeat(MAX_ENTRY_LEN)),
    );
    assert!(matches!(
        a.vault.write(&a.secret, vec![edit]),
        Err(Error::TooLarge { .. })
    ));
}

#[test]
fn schema_is_enforced_at_commit() {
    let mut a = Dev::create();
    let item_err = |e: ItemError| Err(Error::Item(e));
    let create = |kind: &str, fields: Vec<(&str, Field)>| {
        DataOp::create(
            kind,
            None,
            fields.into_iter().map(|(n, f)| (n.to_string(), f)),
        )
    };
    let card = |fields: Vec<(&str, Field)>| {
        let mut all = vec![("number", secret("4242424242424242"))];
        all.extend(fields);
        create("card", all)
    };
    let cases = [
        (
            create("hovercraft", vec![("password", secret("x"))]),
            ItemError::UnknownType("hovercraft".into()),
        ),
        (
            create("ssh", vec![("public-key", text("ssh-ed25519 AAAA"))]),
            ItemError::MissingField("private-key"),
        ),
        (
            create("card", vec![("cvv", secret("123"))]),
            ItemError::MissingField("number"),
        ),
        (
            create(
                "passkey",
                vec![
                    ("rp-id", text("example.com")),
                    ("credential-id", text("AAAA")),
                    ("user-handle", text("a2l0")),
                ],
            ),
            ItemError::MissingField("private-key"),
        ),
        (
            create("login", vec![("password", text("x"))]),
            ItemError::WrongFieldType {
                field: "password".into(),
                expected: FieldType::Secret,
            },
        ),
        (
            create("login", vec![("password", secret(""))]),
            ItemError::InvalidValue {
                field: "password".into(),
                reason: "empty".into(),
            },
        ),
        (
            create(
                "login",
                vec![("password", secret("x")), ("Bad Name", text("x"))],
            ),
            ItemError::InvalidFieldName("Bad Name".into()),
        ),
        (
            create(
                "login",
                vec![
                    ("password", secret("x")),
                    ("x", Field::new(FieldType::Other("future".into()), "v")),
                ],
            ),
            ItemError::UnknownFieldType("future".into()),
        ),
    ];
    for (op, err) in cases {
        assert_eq!(a.vault.write(&a.secret, vec![op]), item_err(err));
    }
    let invalid_values = [
        card(vec![("number", secret("4242 4242 4242 4242"))]),
        card(vec![("number", secret("12345678901"))]),
        card(vec![("number", secret(&"1".repeat(20)))]),
        card(vec![("cvv", secret("12"))]),
        card(vec![("cvv", secret("12a"))]),
        card(vec![("expiry", Field::new(FieldType::Month, "2026-13"))]),
        card(vec![("expiry", Field::new(FieldType::Month, "26-01"))]),
        create(
            "login",
            vec![
                ("password", secret("x")),
                ("url", Field::new(FieldType::Url, "github.com")),
            ],
        ),
        create(
            "login",
            vec![
                ("password", secret("x")),
                ("mail", Field::new(FieldType::Email, "nope")),
            ],
        ),
    ];
    for op in invalid_values {
        let result = a.vault.write(&a.secret, vec![op.clone()]);
        assert!(
            matches!(result, Err(Error::Item(ItemError::InvalidValue { .. }))),
            "{op:?}: {result:?}"
        );
    }
    let named = DataOp::create(
        "login",
        Some(" ".into()),
        [("password".into(), secret("x"))],
    );
    assert_eq!(
        a.vault.write(&a.secret, vec![named]),
        item_err(ItemError::InvalidItemName)
    );
    assert!(a.vault.items().is_empty());
    assert_eq!(a.vault.entries().len(), 1, "nothing was committed");

    // Valid: a full card and extra fields of any type.
    let op = card(vec![
        ("expiry", Field::new(FieldType::Month, "2027-04")),
        ("cvv", secret("1234")),
        ("brand", text("Visa")),
        ("cardholder", text("Dax")),
        ("site", Field::new(FieldType::Url, "https://bank.example")),
        ("recovery", secret("words")),
    ]);
    let entry = a.write(vec![op]);
    let card = ItemId::of_create(&entry.hash(), 0);
    assert_eq!(a.vault.item(&card).unwrap().fields.len(), 7);

    // Valid: a login without a password, a note, an identity with a birthday.
    a.write(vec![
        create("login", vec![("username", text("dax"))]),
        create("note", vec![("notes", secret("line one\nline two"))]),
        create(
            "identity",
            vec![("birthday", Field::new(FieldType::Date, "1990-02-28"))],
        ),
    ]);
    assert!(matches!(
        a.vault.write(
            &a.secret,
            vec![create(
                "identity",
                vec![("birthday", Field::new(FieldType::Date, "1990-02-30"))],
            )],
        ),
        Err(Error::Item(ItemError::InvalidValue { .. }))
    ));
    // Nothing at all is no item, though nothing is required.
    for kind in ["login", "note", "identity"] {
        assert!(matches!(
            a.vault.write(&a.secret, vec![create(kind, vec![])]),
            Err(Error::Item(ItemError::Empty))
        ));
    }

    // Edits.
    let item = a.login("pw");
    let edits = [
        (
            DataOp::remove(item, "Bad Name"),
            ItemError::InvalidFieldName("Bad Name".into()),
        ),
        (
            DataOp::remove(card, "number"),
            ItemError::RequiredField("number".into()),
        ),
        (
            DataOp::set(item, "url", text("https://x.example")),
            ItemError::WrongFieldType {
                field: "url".into(),
                expected: FieldType::Url,
            },
        ),
        (
            DataOp::set(card, "number", secret("42")),
            ItemError::InvalidValue {
                field: "number".into(),
                reason: "must be 12-19 digits".into(),
            },
        ),
        (
            DataOp::name(item, Some("bad\nname".into())),
            ItemError::InvalidItemName,
        ),
        (
            DataOp::set(ItemId::random(), "username", text("x")),
            ItemError::NoSuchItem,
        ),
    ];
    for (op, err) in edits {
        assert_eq!(a.vault.write(&a.secret, vec![op]), item_err(err));
    }
    // One bad op rejects the whole entry.
    let mixed = vec![
        DataOp::set(item, "username", text("dax")),
        DataOp::remove(card, "number"),
    ];
    assert!(a.vault.write(&a.secret, mixed).is_err());
    assert!(!a.vault.item(&item).unwrap().fields.contains_key("username"));
    // Extra fields may change type; removing optional fields is fine.
    a.write(vec![DataOp::set(item, "extra", text("a"))]);
    a.write(vec![DataOp::set(item, "extra", secret("b"))]);
    a.write(vec![DataOp::remove(item, "extra")]);
    a.write(vec![DataOp::remove(item, "never-set")]);
}

#[test]
fn invalid_ops_are_ignored_at_apply_in_any_order() {
    let mut a = Dev::create();
    let item = a.login("orig");
    let mut b = a.invite();
    let mut c = a.invite();
    sync(&a, &mut b);

    a.raw(vec![
        DataOp::remove(item, "Bad Name"),
        DataOp::set(item, "username", text("dax")),
        DataOp::set(item, "password", text("wrong type")),
        DataOp::set(item, "url", Field::new(FieldType::Url, "not a url")),
        DataOp::name(item, Some(String::new())),
        DataOp::name(item, Some("Work".into())),
        DataOp::set(
            item,
            "x",
            Field::new(FieldType::Other("future".into()), "v"),
        ),
    ]);
    let created = b.raw(vec![
        DataOp::create("hovercraft", None, [("password".into(), secret("x"))]),
        DataOp::create("card", None, [("cvv".into(), secret("123"))]),
        DataOp::create(
            "card",
            None,
            [("number".into(), secret("4111111111111111"))],
        ),
        DataOp::set(item, "otp", Field::new(FieldType::Otp, "JBSWY3DPEHPK3PXP")),
    ]);
    let ids: Vec<ItemId> = (0..3)
        .map(|i| ItemId::of_create(&created.hash(), i))
        .collect();
    // c edits b's card without having seen its creation: ignored even when
    // the creation happens to be applied first.
    c.raw(vec![
        DataOp::set(ids[2], "cvv", secret("999")),
        DataOp::remove(ids[2], "number"),
        DataOp::set(item, "notes", Field::new(FieldType::Note, "from c")),
    ]);

    let all = [vec![item], ids.clone()].concat();
    let vault = assert_order_independent(&all_entries(&[&a, &b, &c]), &all);
    let got = vault.item(&item).unwrap();
    assert_eq!(got.kind, "login");
    assert_eq!(got.name.as_deref(), Some("Work"));
    assert_eq!(got.fields["password"], secret("orig"));
    assert_eq!(value(&got, "username"), "dax");
    assert_eq!(value(&got, "notes"), "from c");
    assert_eq!(got.fields["otp"].kind, FieldType::Otp);
    assert!(!got.fields.contains_key("url") && !got.fields.contains_key("x"));
    assert_eq!(vault.item(&ids[0]), None);
    assert_eq!(vault.item(&ids[1]), None);
    let card = vault.item(&ids[2]).unwrap();
    assert_eq!(card.kind, "card");
    assert!(!card.fields.contains_key("cvv"));
    // Ignored ops leave no trace in the history.
    assert!(vault.history(&item).iter().all(|v| match &v.change {
        Change::Remove { field } => field != "Bad Name",
        Change::Set { value, .. } => value.kind != FieldType::Text || value.value == "dax",
        _ => true,
    }));
    assert_eq!(vault.items().len(), 2);
}

#[test]
fn name_set_and_clear_resolve_like_fields() {
    let mut a = Dev::create();
    let mut b = a.invite();
    let fields = [("password".into(), secret("p"))];
    let (item, _) = a
        .vault
        .create_item(&a.secret, "login", Some("Personal".into()), fields)
        .unwrap();
    sync(&a, &mut b);
    assert_eq!(
        b.vault.item(&item).unwrap().name.as_deref(),
        Some("Personal")
    );

    let clear = a.write(vec![DataOp::name(item, None)]);
    let set = b.write(vec![DataOp::name(item, Some("Work".into()))]);
    sync_both(&mut a, &mut b);
    let expected = if clear.hash() > set.hash() {
        None
    } else {
        Some("Work")
    };
    let vault = assert_order_independent(&all_entries(&[&a, &b]), &[item]);
    for vault in [&vault, &a.vault, &b.vault] {
        assert_eq!(vault.item(&item).unwrap().name.as_deref(), expected);
        let conflicted = vault
            .history(&item)
            .into_iter()
            .filter(|v| v.status == VersionStatus::Conflicted)
            .count();
        assert_eq!(conflicted, 1);
    }

    // Based on both, so it wins.
    a.write(vec![DataOp::name(item, None)]);
    sync(&a, &mut b);
    assert_eq!(b.vault.item(&item).unwrap().name, None);
    b.write(vec![DataOp::name(item, Some("Again".into()))]);
    sync(&b, &mut a);
    assert_eq!(a.vault.item(&item).unwrap().name.as_deref(), Some("Again"));
}

#[test]
fn field_type_travels_with_the_winning_value() {
    let mut a = Dev::create();
    let item = a.login("p");
    let mut b = a.invite();
    let ea = a.write(vec![DataOp::set(item, "extra", text("plain"))]);
    let eb = b.write(vec![DataOp::set(
        item,
        "extra",
        Field::new(FieldType::Email, "x@y.example"),
    )]);
    sync_both(&mut a, &mut b);
    let (winner, loser) = if ea.hash() > eb.hash() {
        (text("plain"), Field::new(FieldType::Email, "x@y.example"))
    } else {
        (Field::new(FieldType::Email, "x@y.example"), text("plain"))
    };
    for vault in [&a.vault, &b.vault] {
        assert_eq!(vault.item(&item).unwrap().fields["extra"], winner);
        let history = vault.history(&item);
        let find = |f: &Field| {
            history
                .iter()
                .find(|v| matches!(&v.change, Change::Set { value, .. } if value == f))
                .unwrap()
                .status
        };
        assert_eq!(find(&winner), VersionStatus::Current);
        assert_eq!(find(&loser), VersionStatus::Conflicted);
    }
}

#[test]
fn edit_based_on_previous_value_replaces_it() {
    let mut a = Dev::create();
    let mut b = a.invite();
    let item = a.login("init");
    for round in 0..8 {
        a.set(item, "password", &format!("a{round}"));
        sync(&a, &mut b);
        b.set(item, "password", &format!("b{round}"));
        sync(&b, &mut a);
        assert_eq!(
            value(&a.vault.item(&item).unwrap(), "password"),
            format!("b{round}")
        );
    }
    assert!(
        a.vault
            .history(&item)
            .iter()
            .all(|v| v.status != VersionStatus::Conflicted)
    );
}

#[test]
fn concurrent_edits_pick_hash_winner_and_keep_loser() {
    let mut a = Dev::create();
    let mut b = a.invite();
    let item = a.login("p0");
    a.set(item, "username", "dax");
    sync(&a, &mut b);
    let ea = a.set(item, "password", "from-a");
    let eb = b.set(item, "password", "from-b");
    sync_both(&mut a, &mut b);

    let (winner, loser) = if ea.hash() > eb.hash() {
        (ea, eb)
    } else {
        (eb, ea)
    };
    let set_value = |e: &Entry| match e.payload() {
        Payload::Data(ops) => match &ops[0] {
            DataOp::Edit {
                change: Change::Set { value, .. },
                ..
            } => value.value.clone(),
            _ => unreachable!(),
        },
        _ => unreachable!(),
    };
    for vault in [&a.vault, &b.vault] {
        assert_eq!(
            value(&vault.item(&item).unwrap(), "password"),
            set_value(&winner)
        );
        let history = vault.history(&item);
        let status = |h: Hash| history.iter().find(|v| v.entry == h).unwrap().status;
        assert_eq!(status(winner.hash()), VersionStatus::Current);
        assert_eq!(status(loser.hash()), VersionStatus::Conflicted);
    }
    assert_eq!(a.vault.history(&item), b.vault.history(&item));

    // A later edit based on both resolves the conflict.
    a.set(item, "password", "merged");
    sync(&a, &mut b);
    assert_eq!(value(&b.vault.item(&item).unwrap(), "password"), "merged");
    let history = b.vault.history(&item);
    assert_eq!(
        history
            .iter()
            .filter(|v| v.status == VersionStatus::Conflicted)
            .count(),
        0
    );
}

#[test]
fn concurrent_edits_to_different_fields_both_survive() {
    let mut a = Dev::create();
    let item = a.login("p");
    let mut b = a.invite();
    a.set(item, "username", "dax");
    b.set(item, "url", "https://github.com");
    sync_both(&mut a, &mut b);
    for vault in [&a.vault, &b.vault] {
        let got = vault.item(&item).unwrap();
        assert_eq!(value(&got, "username"), "dax");
        assert_eq!(value(&got, "url"), "https://github.com");
    }
}

#[test]
fn concurrent_edits_are_order_independent() {
    let mut a = Dev::create();
    let items = [a.login("x"), a.login("y")];
    let mut b = a.invite();
    let mut c = a.invite();
    sync(&a, &mut b);
    for (i, dev) in [&mut a, &mut b, &mut c].into_iter().enumerate() {
        dev.set(items[0], "password", &format!("p{i}"));
        dev.set(items[1], "user", &format!("u{i}"));
        dev.write(vec![DataOp::remove(items[1], "user")]);
        dev.set(items[1], "user", &format!("again{i}"));
    }
    sync_both(&mut a, &mut b);
    a.write(vec![DataOp::delete(items[0])]);
    c.set(items[1], "notes", "c");
    let vault = assert_order_independent(&all_entries(&[&a, &b, &c]), &items);
    let conflicted = vault
        .history(&items[1])
        .iter()
        .filter(|v| v.status == VersionStatus::Conflicted)
        .count();
    assert_eq!(conflicted, 2);
}

#[test]
fn concurrent_edit_beats_delete_item() {
    let mut a = Dev::create();
    let mut b = a.invite();
    let item = a.login("one");
    sync(&a, &mut b);
    a.write(vec![DataOp::delete(item)]);
    b.set(item, "password", "two");
    sync_both(&mut a, &mut b);
    for vault in [&a.vault, &b.vault] {
        let got = vault.item(&item).unwrap();
        assert!(!got.deleted);
        assert_eq!(value(&got, "password"), "two");
        let delete = vault
            .history(&item)
            .into_iter()
            .find(|v| v.change == Change::Delete)
            .unwrap();
        assert_eq!(delete.status, VersionStatus::Conflicted);
    }
}

#[test]
fn removal_cutoff_ignores_later_entries() {
    let mut a = Dev::create();
    let mut b = a.invite();
    let mut c = a.invite();
    let item = b.login("seen");
    sync(&b, &mut a);
    b.set(item, "password", "unseen");
    b.login("unseen");
    let removal = a.remove(b.id());
    assert_eq!(
        removal.payload(),
        &Payload::Membership(MembershipOp::Remove {
            device: b.id(),
            last_seen_seq: Some(0)
        })
    );
    sync_both(&mut a, &mut b);
    sync(&a, &mut c);
    for vault in [&a.vault, &b.vault, &c.vault] {
        assert_eq!(value(&vault.item(&item).unwrap(), "password"), "seen");
        assert_eq!(vault.items().len(), 1);
    }

    // c built on b's unseen write before learning of the removal: c's own
    // edit counts, b's does not.
    let mut a2 = Dev::create();
    let item = a2.login("orig");
    let mut b2 = a2.invite();
    let mut c2 = a2.invite();
    sync(&a2, &mut b2);
    b2.set(item, "password", "b");
    sync(&b2, &mut c2);
    c2.set(item, "notes", "c");
    a2.remove(b2.id());
    sync_both(&mut a2, &mut c2);
    let vault = assert_order_independent(&all_entries(&[&a2, &b2, &c2]), &[item]);
    let got = vault.item(&item).unwrap();
    assert_eq!(value(&got, "password"), "orig");
    assert_eq!(value(&got, "notes"), "c");
}

#[test]
fn removal_without_seen_entries_ignores_all() {
    let mut a = Dev::create();
    let mut b = a.invite();
    let item = b.login("x");
    let removal = a.remove(b.id());
    assert_eq!(
        removal.payload(),
        &Payload::Membership(MembershipOp::Remove {
            device: b.id(),
            last_seen_seq: None
        })
    );
    sync(&b, &mut a);
    assert_eq!(a.vault.item(&item), None);
}

#[test]
fn concurrent_removals_keep_the_larger_cutoff() {
    let mut a = Dev::create();
    let mut b = a.invite();
    let mut c = a.invite();
    sync(&a, &mut b);
    let item = b.login("0");
    sync(&b, &mut a);
    b.set(item, "password", "1");
    sync(&b, &mut c);
    a.remove(b.id());
    c.remove(b.id());
    let vault = assert_order_independent(&all_entries(&[&a, &b, &c]), &[item]);
    assert_eq!(value(&vault.item(&item).unwrap(), "password"), "1");
    assert!(!vault.is_member(&b.id()));
}

#[test]
fn data_from_device_with_cut_admission_is_ignored() {
    let mut a = Dev::create();
    let mut b = a.invite();
    let mut d = b.invite();
    let item = d.login("d");
    a.remove(b.id());
    sync(&d, &mut b);
    sync_both(&mut a, &mut b);
    assert_eq!(a.vault.item(&item), None);
    assert!(!a.vault.is_member(&d.id()));
}

// ---- sync -----------------------------------------------------------------

#[test]
fn missing_for_sends_membership_first_and_converges() {
    let mut a = Dev::create();
    let item = a.login("p");
    let mut b = a.invite();
    a.set(item, "f", "a");
    b.set(item, "g", "b");
    let joiner = DeviceSecret::generate();
    a.vault
        .add(
            &a.secret,
            joiner.device_id(),
            joiner.join_consent(&a.vault.id(), &a.id()),
        )
        .unwrap();
    a.set(item, "h", "a");

    let missing = a.vault.missing_for(&b.vault.heads());
    let logs: Vec<Log> = missing.iter().map(|e| e.log()).collect();
    assert_eq!(logs, [Log::Membership, Log::Data, Log::Data]);

    sync_both(&mut a, &mut b);
    assert_eq!(a.vault.heads(), b.vault.heads());
    assert_eq!(a.vault.item(&item), b.vault.item(&item));
    assert!(a.vault.missing_for(&b.vault.heads()).is_empty());

    let reloaded = Vault::load(a.vault.entries().into_iter().cloned()).unwrap();
    assert_eq!(snapshot(&reloaded, &[item]), snapshot(&a.vault, &[item]));
}

#[test]
fn heads_encoding_round_trips() {
    let mut a = Dev::create();
    let _b = a.invite();
    a.login("v");
    let heads = a.vault.heads();
    assert_eq!(heads.iter().count(), 2);
    assert_eq!(Heads::decode(&heads.encode()), Ok(heads.clone()));
    let mut bytes = heads.encode();
    bytes.push(0);
    assert_eq!(Heads::decode(&bytes), Err(DecodeError::TrailingBytes));

    let author = a.id();
    let unsorted = [
        &2u32.to_be_bytes()[..],
        author.as_bytes(),
        &[1],
        &0u64.to_be_bytes(),
        author.as_bytes(),
        &[0],
        &0u64.to_be_bytes(),
    ]
    .concat();
    assert_eq!(Heads::decode(&unsorted), Err(DecodeError::NotCanonical));
}

#[test]
fn a_mirror_keeps_its_source_apart_from_its_fields() {
    let mut a = Dev::create();
    let source = |version: &str| Source {
        id: "1password/acct/vault/item".into(),
        version: version.into(),
    };
    let entry = a.write(vec![DataOp::create_mirror(
        "login",
        Some("GitHub".into()),
        [("password".into(), secret("p"))],
        source("1"),
    )]);
    let id = ItemId::of_create(&entry.hash(), 0);
    let item = a.vault.item(&id).unwrap();
    assert_eq!(item.source, Some(source("1")));
    assert_eq!(item.fields.keys().collect::<Vec<_>>(), ["password"]);
    assert!(
        a.vault
            .history(&id)
            .iter()
            .any(|v| v.change == Change::Source(Some(source("1"))))
    );

    let mut b = a.invite();
    b.write(vec![DataOp::source(id, Some(source("2")))]);
    sync_both(&mut a, &mut b);
    assert_eq!(a.vault.item(&id).unwrap().source, Some(source("2")));

    // Clearing the source makes it the user's own; a reload agrees.
    a.write(vec![DataOp::source(id, None)]);
    let reloaded = Vault::load(a.vault.entries().into_iter().cloned()).unwrap();
    assert_eq!(reloaded.item(&id).unwrap().source, None);

    // The user's own items have none.
    let own = a.login("x");
    assert_eq!(a.vault.item(&own).unwrap().source, None);
}

#[test]
fn invalid_sources_are_rejected() {
    let version = |n| Source {
        id: "1password/a/v/i".into(),
        version: "x".repeat(n),
    };
    assert!(crate::item::valid_source(&version(2048)));
    assert!(!crate::item::valid_source(&version(2049)));
    let mut a = Dev::create();
    let id = a.login("x");
    let blank = Source {
        id: String::new(),
        version: "1".into(),
    };
    assert_eq!(
        a.vault
            .write(&a.secret, vec![DataOp::source(id, Some(blank.clone()))])
            .unwrap_err(),
        Error::Item(ItemError::InvalidSource)
    );
    assert_eq!(
        a.vault
            .write(
                &a.secret,
                vec![DataOp::create_mirror("note", Some("n".into()), [], blank)]
            )
            .unwrap_err(),
        Error::Item(ItemError::InvalidSource)
    );
}
