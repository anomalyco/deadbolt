use std::collections::BTreeSet;

use proptest::prelude::*;

use crate::tag::{
    MAX_TAG_LEN, MAX_TAGS, Query, import_tag, item_has_tag, normalize_tag, tag_counts, tag_matches,
    valid_tag,
};
use crate::*;

struct Peer {
    secret: DeviceSecret,
    vault: Vault,
}

impl Peer {
    fn create() -> Self {
        let secret = DeviceSecret::generate();
        let (vault, _) = Vault::create(&secret, "personal").unwrap();
        Self { secret, vault }
    }

    fn invite(&mut self) -> Self {
        let secret = DeviceSecret::generate();
        let consent = secret.join_consent(&self.vault.id(), &self.secret.device_id());
        self.vault
            .add(&self.secret, secret.device_id(), consent)
            .unwrap();
        let vault = Vault::load(self.vault.entries().into_iter().cloned()).unwrap();
        Self { secret, vault }
    }

    fn write(&mut self, ops: Vec<DataOp>) -> Entry {
        self.vault.write(&self.secret, ops).unwrap()
    }
}

fn sync(from: &Peer, to: &mut Peer) {
    for entry in from.vault.missing_for(&to.vault.heads()) {
        to.vault.apply(entry.clone()).unwrap();
    }
}

fn sync_both(a: &mut Peer, b: &mut Peer) {
    sync(a, b);
    sync(b, a);
}

fn all_entries(peers: &[&Peer]) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::new();
    for p in peers {
        for e in p.vault.entries() {
            if !out.iter().any(|x| x.hash() == e.hash()) {
                out.push(e.clone());
            }
        }
    }
    out
}

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

#[test]
fn normalizes_and_validates_nested_tags() {
    assert_eq!(
        normalize_tag("  #Work / AWS / Prod "),
        Some("Work/AWS/Prod".into())
    );
    assert_eq!(normalize_tag("Tax   2026"), Some("Tax 2026".into()));
    for bad in ["", "  ", "#", "#/", "/work", "work/", "work//aws"] {
        assert_eq!(normalize_tag(bad), None, "{bad:?}");
    }
    let at_cap = "x".repeat(MAX_TAG_LEN);
    assert!(valid_tag(&at_cap));
    assert!(!valid_tag(&"x".repeat(MAX_TAG_LEN + 1)));
    assert!(!valid_tag("#work"));
    assert!(!valid_tag("work\naws"));
    assert!(!valid_tag("work  aws"));

    // Export cleanup tolerates trailing slashes and overlong folder names.
    assert_eq!(import_tag(" /Work//AWS/ "), Some("Work/AWS".into()));
    let long = format!("Work/{}", "a".repeat(200));
    assert_eq!(import_tag(&long).unwrap().chars().count(), MAX_TAG_LEN);
}

#[test]
fn matches_nested_segments_and_parses_queries() {
    assert!(tag_matches("Work/AWS/Prod", "work"));
    assert!(tag_matches("Work/AWS/Prod", "#work/aws"));
    assert!(tag_matches("Tax 2026/Federal", "tax-2026"));
    assert!(!tag_matches("network", "work"));
    assert!(!tag_matches("work", "work/aws"));

    let q = Query::parse(r#"#work/aws #"Tax 2026" is:favorite github"#);
    assert_eq!(q.tags, ["work/aws", "Tax 2026"]);
    assert!(q.favorite);
    assert!(!q.any_tag);
    assert_eq!(q.words, ["github"]);

    let typing = Query::parse("#");
    assert!(typing.any_tag && typing.tags.is_empty());

    let counts = tag_counts([
        vec!["Work/AWS", "Work/GCP"],
        vec!["work/aws", "Personal"],
        vec!["Work"],
    ]);
    assert_eq!(
        counts,
        [
            ("Personal".into(), 1),
            ("Work".into(), 3),
            ("Work/AWS".into(), 2),
            ("Work/GCP".into(), 1),
        ]
    );
    assert!(item_has_tag(["Work/AWS"], "work"));
}

#[test]
fn canonical_encoding_preserves_legacy_hashes_and_rejects_non_canonical_creates() {
    let secret = DeviceSecret::from_bytes(&[9; 32]);
    let vault = VaultId::from_bytes([1; 32]);
    let pw = ("password".into(), Field::new(FieldType::Secret, "pw"));

    let plain = DataOp::create("login", Some("GitHub".into()), [pw.clone()]);
    let plain_bytes = Entry::sign(&secret, vault, 0, [], Payload::Data(vec![plain])).encode();
    // Payload tag (1) + op count (4) -> op tag must remain 0x00.
    let op_tag_at = 32 + 32 + 8 + 4 + 1 + 4;
    assert_eq!(plain_bytes[op_tag_at], 0);

    let full = DataOp::create_with(
        "login",
        Some("GitHub".into()),
        [pw.clone()],
        Some(Source {
            id: "1password/a/v/i".into(),
            version: "1".into(),
        }),
        true,
        ["work/aws".into(), "dev".into()],
    );
    let entry = Entry::sign(&secret, vault, 0, [], Payload::Data(vec![full]));
    let bytes = entry.encode();
    assert_eq!(bytes[op_tag_at], 3);
    let decoded = Entry::decode(&bytes).unwrap();
    assert_eq!(decoded, entry);
    assert_eq!(decoded.encode(), bytes);

    // Tag 0x03 with favorite=false and 0 tags is non-canonical (belongs on 0x00/0x02).
    let mut non_canonical = Entry::sign(
        &secret,
        vault,
        0,
        [],
        Payload::Data(vec![DataOp::create_with(
            "login",
            None,
            [pw],
            None,
            true,
            Vec::<String>::new(),
        )]),
    )
    .encode();
    // Last two bytes before the 64-byte signature are fav=1, tags_len=0(u32): flip fav to 0.
    let fav_at = non_canonical.len() - 64 - 5;
    assert_eq!(non_canonical[fav_at], 1);
    non_canonical[fav_at] = 0;
    assert_eq!(
        Entry::decode(&non_canonical),
        Err(DecodeError::NotCanonical)
    );
}

#[test]
fn concurrent_tags_and_favorites_converge_without_interfering() {
    let mut a = Peer::create();
    let mut b = a.invite();
    let (id, _) = a
        .vault
        .create_item_with(
            &a.secret,
            "login",
            Some("AWS".into()),
            [("password".into(), Field::new(FieldType::Secret, "p1"))],
            true,
            ["work".into()],
        )
        .unwrap();
    sync(&a, &mut b);
    assert!(b.vault.item(&id).unwrap().favorite);
    assert_eq!(
        b.vault.item(&id).unwrap().tags,
        BTreeSet::from(["work".into()])
    );

    // A unstars and adds work/aws; B updates password and adds prod.
    a.write(vec![
        DataOp::favorite(id, false),
        DataOp::tag_add(id, "work/aws"),
    ]);
    b.write(vec![
        DataOp::set(id, "password", Field::new(FieldType::Secret, "p2")),
        DataOp::tag_add(id, "prod"),
    ]);
    sync_both(&mut a, &mut b);

    for p in [&a, &b] {
        let item = p.vault.item(&id).unwrap();
        assert!(!item.favorite);
        assert_eq!(item.fields["password"].value, "p2");
        assert_eq!(
            item.tags,
            BTreeSet::from(["prod".into(), "work".into(), "work/aws".into()])
        );
    }

    // Add-wins OR-Set: A re-adds "work" concurrently with B removing "work".
    a.write(vec![DataOp::tag_add(id, "Work")]);
    b.write(vec![DataOp::tag_remove(id, "work")]);
    sync_both(&mut a, &mut b);
    for p in [&a, &b] {
        let item = p.vault.item(&id).unwrap();
        assert!(item.tags.contains("Work") && !item.tags.contains("work"));
        let rm = p
            .vault
            .history(&id)
            .into_iter()
            .find(|v| v.change == Change::TagRemove("work".into()))
            .unwrap();
        assert_eq!(rm.status, VersionStatus::Conflicted);
    }

    // Causal remove after seeing both removes "Work" case-insensitively.
    b.write(vec![DataOp::tag_remove(id, "work")]);
    sync_both(&mut a, &mut b);
    for p in [&a, &b] {
        assert!(!p.vault.item(&id).unwrap().tags.contains("Work"));
    }
}

#[test]
fn enforces_tag_limits_and_ranks_favorites_first_in_autofill_and_forms() {
    let mut a = Peer::create();
    let pw = [("password".into(), Field::new(FieldType::Secret, "pw"))];
    let bad = DataOp::create_with("login", None, pw.clone(), None, false, ["#bad".into()]);
    assert!(matches!(
        a.vault.write(&a.secret, vec![bad]),
        Err(Error::Item(ItemError::InvalidTag(_)))
    ));
    let over: Vec<String> = (0..=MAX_TAGS).map(|i| format!("t{i}")).collect();
    let too_many = DataOp::create_with("login", None, pw, None, false, over);
    assert_eq!(
        a.vault.write(&a.secret, vec![too_many]),
        Err(Error::Item(ItemError::TooManyTags))
    );

    // Autofill: closeness still beats favorite; at equal closeness, favorite wins.
    let (plain_login, _) = a
        .vault
        .create_item(
            &a.secret,
            "login",
            Some("Alpha".into()),
            [("url".into(), Field::new(FieldType::Url, "https://acme.com"))],
        )
        .unwrap();
    let (fav_login, _) = a
        .vault
        .create_item_with(
            &a.secret,
            "login",
            Some("Zeta".into()),
            [("url".into(), Field::new(FieldType::Url, "https://acme.com"))],
            true,
            ["work".into()],
        )
        .unwrap();
    let r_plain = autofill::rank("https://acme.com", &a.vault.item(&plain_login).unwrap(), 99);
    let r_fav = autofill::rank("https://acme.com", &a.vault.item(&fav_login).unwrap(), 0);
    assert!(r_fav < r_plain, "favorite outranks recent non-favorite");
    assert!(listing::searchable(&a.vault.item(&fav_login).unwrap()).contains(&"work".to_string()));

    // Forms: favorite card comes ahead of alphabetically earlier card.
    a.vault
        .create_item(
            &a.secret,
            "card",
            Some("Amex".into()),
            [(
                "number".into(),
                Field::new(FieldType::Secret, "378282246310005"),
            )],
        )
        .unwrap();
    a.vault
        .create_item_with(
            &a.secret,
            "card",
            Some("Visa".into()),
            [(
                "number".into(),
                Field::new(FieldType::Secret, "4242424242424242"),
            )],
            true,
            [],
        )
        .unwrap();
    let (_, cards) = forms::list(&[&a.vault], &["card"]);
    assert_eq!(cards[0].title, "Visa");
    assert!(cards[0].favorite);
}

#[derive(Clone, Debug)]
enum Step {
    Fav(usize, bool),
    AddTag(usize, usize),
    RmTag(usize, usize),
    Sync(usize, usize),
}

fn sync_idx(peers: &mut [Peer], from: usize, to: usize) {
    if from == to {
        return;
    }
    let missing: Vec<Entry> = peers[from]
        .vault
        .missing_for(&peers[to].vault.heads())
        .into_iter()
        .cloned()
        .collect();
    for e in missing {
        peers[to].vault.apply(e).unwrap();
    }
}

proptest! {
    #[test]
    fn tag_and_favorite_dags_converge_in_every_causal_order(
        steps in proptest::collection::vec(
            prop_oneof![
                (0..3usize, any::<bool>()).prop_map(|(d, f)| Step::Fav(d, f)),
                (0..3usize, 0..6usize).prop_map(|(d, t)| Step::AddTag(d, t)),
                (0..3usize, 0..6usize).prop_map(|(d, t)| Step::RmTag(d, t)),
                (0..3usize, 0..3usize).prop_map(|(a, b)| Step::Sync(a, b)),
            ],
            1..28
        )
    ) {
        const TAGS: [&str; 6] = ["work", "Work", "work/aws", "Work/AWS", "prod", "Tax 2026"];
        let mut p0 = Peer::create();
        let p1 = p0.invite();
        let p2 = p0.invite();
        let mut peers = [p0, p1, p2];
        sync_idx(&mut peers, 0, 1);
        sync_idx(&mut peers, 0, 2);
        let (item, _) = peers[0]
            .vault
            .create_item(
                &peers[0].secret,
                "login",
                Some("GitHub".into()),
                [("password".into(), Field::new(FieldType::Secret, "pw"))],
            )
            .unwrap();
        sync_idx(&mut peers, 0, 1);
        sync_idx(&mut peers, 0, 2);

        for step in steps {
            match step {
                Step::Fav(d, f) => {
                    peers[d].write(vec![DataOp::favorite(item, f)]);
                }
                Step::AddTag(d, t) => {
                    peers[d].write(vec![DataOp::tag_add(item, TAGS[t])]);
                }
                Step::RmTag(d, t) => {
                    peers[d].write(vec![DataOp::tag_remove(item, TAGS[t])]);
                }
                Step::Sync(a, b) => sync_idx(&mut peers, a, b),
            }
        }

        let entries = all_entries(&[&peers[0], &peers[1], &peers[2]]);
        let forward = apply_in_order(entries.clone());
        let mut rev = vec![entries[0].clone()];
        rev.extend(entries[1..].iter().rev().cloned());
        let backward = apply_in_order(rev);

        prop_assert_eq!(forward.item(&item), backward.item(&item));
        prop_assert_eq!(forward.history(&item), backward.history(&item));
    }
}
