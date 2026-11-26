use deadbolt_core::v2::{DeviceKeys, RecoverySecret};
use deadbolt_core::{Author, Change, DataOp, Error, Field, FieldType, Vault};
use deadbolt_pack::{MemBlocks, PackReader, pack};

use super::NOW;
use crate::{PackViewer, ViewerError, item_key, pack_input, site_key};

fn fixture(
    kind: &str,
    name: Option<&str>,
    url: Option<&str>,
    deleted: bool,
) -> (MemBlocks, crate::ViewerKeyBundle, String) {
    let author = Author::new(DeviceKeys::from_seed(&[51; 32]), NOW * 1000);
    let (mut vault, _) = Vault::create(
        &RecoverySecret::from_bytes([52; 32]),
        &author,
        "viewer",
        "test",
    )
    .unwrap();
    let mut fields = vec![
        ("username".into(), Field::new(FieldType::Text, "alex")),
        ("password".into(), Field::new(FieldType::Secret, "root-pw")),
    ];
    if let Some(url) = url {
        fields.push(("url".into(), Field::new(FieldType::Url, url)));
    }
    if kind == "api" {
        fields.push((
            "credential".into(),
            Field::new(FieldType::Secret, "api-key"),
        ));
    }
    if kind == "passkey" {
        for (field, value) in [
            ("rp-id", "other.com"),
            ("credential-id", "cred"),
            ("user-handle", "handle"),
        ] {
            fields.push((field.into(), Field::new(FieldType::Text, value)));
        }
        fields.push(("private-key".into(), Field::new(FieldType::Secret, "pkcs8")));
    }
    let (id, _) = vault
        .transact(
            |w| w.create_item(&author, kind, name.map(str::to_owned), fields),
            |_, _| Ok::<_, Error>(()),
        )
        .unwrap();
    if deleted {
        vault
            .transact(
                |w| {
                    w.write(
                        &author,
                        vec![DataOp::Edit {
                            item: id,
                            change: Change::Delete { at: Some(NOW) },
                        }],
                    )
                },
                |_, _| Ok::<_, Error>(()),
            )
            .unwrap();
    }
    let blocks = MemBlocks::new();
    let mut bundle = None;
    vault
        .transact(
            |w| {
                w.checkpoint(&author, |core, site| {
                    let input = pack_input(core, site, 1).map_err(|e| e.to_string())?;
                    let summary = pack::write(&blocks, "gen-1.pack", &input, site.key.as_bytes())
                        .map_err(|e| e.to_string())?;
                    bundle = Some(crate::ViewerKeyBundle::derive_for_pack(
                        &site.key,
                        &summary.header,
                        &super::device_kem().public_key(),
                        super::EXPIRES,
                    ));
                    Ok(Vec::new())
                })
            },
            |_, _| Ok::<_, Error>(()),
        )
        .unwrap();
    (
        blocks,
        bundle.unwrap(),
        deadbolt_pack::names::hex(id.as_bytes()),
    )
}

#[test]
fn deleted_and_non_autofill_items_are_never_indexed_or_decrypted() {
    for (kind, deleted) in [
        ("login", true),
        ("server", false),
        ("api", false),
        ("database", false),
        ("wifi", false),
        ("membership", false),
    ] {
        let (blocks, bundle, id) =
            fixture(kind, Some("Hidden"), Some("https://example.com"), deleted);
        let keys = bundle.pack_keys();
        let reader = PackReader::open(&blocks, "gen-1.pack").unwrap();
        let index = reader.read_index(&keys).unwrap();
        assert!(
            index
                .lookup_by_key(&keys, &site_key("example.com"))
                .is_empty(),
            "{kind}"
        );
        let item =
            index.lookup_by_key(&keys, &item_key(&crate::item::parse_item_id(&id).unwrap()))[0];
        // The secret exists but is corrupt: rejecting eligibility must precede reading it.
        blocks.flip_bit("gen-1.pack", item.secret.off as usize + 40, 3);
        let viewer = PackViewer::open(&blocks, &bundle, NOW).unwrap();
        assert!(viewer.lookup_site("example.com").unwrap().is_empty());
        assert_eq!(viewer.lookup_item(&id).unwrap(), None);
        blocks.take_reads();
        assert_eq!(
            viewer.fill_secret(&id),
            Err(ViewerError::NotFound),
            "{kind}"
        );
        let reads = blocks.take_reads();
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0].offset, item.head.off);
    }
}

#[test]
fn unnamed_logins_use_the_url_host_then_username() {
    for name in [None, Some("Example")] {
        let (blocks, bundle, id) =
            fixture("login", name, Some("https://www.example.com/login"), false);
        let viewer = PackViewer::open(&blocks, &bundle, NOW).unwrap();
        assert_eq!(
            viewer.lookup_site("example.com").unwrap()[0].title,
            name.unwrap_or("example.com")
        );
        assert_eq!(
            viewer.lookup_item(&id).unwrap().unwrap().title,
            name.unwrap_or("example.com")
        );
    }
    let (blocks, bundle, id) = fixture("login", None, None, false);
    let viewer = PackViewer::open(&blocks, &bundle, NOW).unwrap();
    assert_eq!(viewer.lookup_item(&id).unwrap().unwrap().title, "alex");
}

#[test]
fn passkeys_match_only_their_relying_party_even_with_a_saved_url() {
    let (blocks, bundle, id) = fixture("passkey", None, Some("https://example.com"), false);
    let reader = PackReader::open(&blocks, "gen-1.pack").unwrap();
    let keys = bundle.pack_keys();
    assert!(
        reader
            .read_index(&keys)
            .unwrap()
            .lookup_by_key(&keys, &site_key("example.com"))
            .is_empty()
    );
    let viewer = PackViewer::open(&blocks, &bundle, NOW).unwrap();
    assert!(viewer.lookup_site("example.com").unwrap().is_empty());
    assert_eq!(viewer.lookup_rp("other.com").unwrap()[0].title, "other.com");
    assert!(viewer.fill_secret(&id).unwrap().passkey.is_some());
}

#[test]
fn a_passkey_without_a_relying_party_still_does_not_index_urls() {
    let with_login = super::core_pack(2);
    let url = with_login
        .state
        .items
        .values()
        .find_map(|item| item.fields.get("url"))
        .unwrap()
        .clone();
    let mut core = super::core_pack(1);
    let item = core.state.items.values_mut().next().unwrap();
    item.fields.insert("url".into(), url);
    item.fields.remove("@name");
    item.fields.remove("rp-id");
    let records = core.split().unwrap();
    let head = deadbolt_core::v2::pack::ItemHead::decode(&records.items[0].head).unwrap();
    let hit = crate::ViewerHit::from_head(&head).unwrap();
    assert_eq!(hit.title, "user0@example.com");
    assert_eq!(
        crate::item::keys_of(head.id.as_bytes(), Some(&hit)).unwrap(),
        [item_key(head.id.as_bytes())]
    );
}
