use zeroize::Zeroizing;

use super::{EPOCH, EPOCH_KEY, VAULT, keys_for};
use crate::blocks::ReadOp;
use crate::pack::{self, HEADER_LEN, PACK_MAGIC, RecordRef, Tag, open_record};
use crate::{
    Blocks, Error, MemBlocks, PackHeader, PackId, PackInput, PackItem, PackKeys, PackReader,
};

const NAME: &str = "gen-1.pack";
const ITEMS: usize = 1000;

fn secret(i: usize) -> Vec<u8> {
    format!("secret {i}: {}", "x".repeat(i % 50)).into_bytes()
}

fn big_input() -> PackInput {
    PackInput {
        vault: VAULT,
        author: [2; 32],
        seq: 42,
        epoch: EPOCH,
        generation: 1,
        meta: Zeroizing::new(b"frontier and clocks".to_vec()),
        items: (0..ITEMS)
            .map(|i| PackItem {
                keys: vec![
                    format!("item-{i}").into_bytes(),
                    format!("site-{}.example", i % 300).into_bytes(),
                ],
                head: Zeroizing::new(format!("head {i}").into_bytes()),
                secret: Zeroizing::new(secret(i)),
            })
            .collect(),
    }
}

fn written() -> (MemBlocks, pack::PackSummary) {
    let blocks = MemBlocks::new();
    let summary = pack::write(&blocks, NAME, &big_input(), &EPOCH_KEY).unwrap();
    (blocks, summary)
}

#[test]
fn the_header_is_fixed_and_names_the_pack() {
    let (blocks, summary) = written();
    let bytes = blocks.file(NAME).unwrap();
    assert_eq!(bytes.len() as u64, summary.len);
    assert_eq!(bytes[..8], PACK_MAGIC);
    let header = PackHeader::decode(&bytes).unwrap();
    assert_eq!(header, summary.header);
    assert_eq!(header.encode().len(), HEADER_LEN);
    assert_eq!(
        (header.seq, header.generation, header.record_count),
        (42, 1, 2 + 2 * ITEMS as u32)
    );
    assert_eq!(
        summary.id,
        PackId(blake3::hash(&bytes[..HEADER_LEN]).into())
    );
    let body = &bytes[..bytes.len() - 32];
    assert_eq!(summary.hash, <[u8; 32]>::from(blake3::hash(body)));
    assert_eq!(bytes[body.len()..], summary.hash);
    let reader = PackReader::open(&blocks, NAME).unwrap();
    assert_eq!(reader.verify_trailer().unwrap(), summary.hash);
}

#[test]
fn a_lookup_reads_only_the_index_and_one_secret() {
    let (blocks, summary) = written();
    let reader = PackReader::open(&blocks, NAME).unwrap();
    assert_eq!(
        blocks.take_reads(),
        [ReadOp {
            name: NAME.into(),
            offset: 0,
            len: HEADER_LEN as u64
        }]
    );
    let keys = keys_for(&reader);

    let index = reader.read_index(&keys).unwrap();
    let hits = index.lookup_by_key(&keys, b"item-500");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].item, 500);
    assert_eq!(
        &reader.read_secret(&keys, &hits[0]).unwrap()[..],
        secret(500)
    );

    let header = summary.header;
    assert_eq!(
        blocks.take_reads(),
        [
            ReadOp {
                name: NAME.into(),
                offset: header.index_off,
                len: u64::from(header.index_len)
            },
            ReadOp {
                name: NAME.into(),
                offset: hits[0].secret.off,
                len: u64::from(hits[0].secret.len)
            },
        ]
    );
    assert_eq!(&reader.read_head(&keys, &hits[0]).unwrap()[..], b"head 500");
}

#[test]
fn every_item_opens_and_shared_keys_find_every_match() {
    let (blocks, _) = written();
    let reader = PackReader::open(&blocks, NAME).unwrap();
    let keys = keys_for(&reader);
    assert_eq!(
        &reader.read_meta(&keys).unwrap()[..],
        b"frontier and clocks"
    );
    let index = reader.read_index(&keys).unwrap();
    assert_eq!(
        (index.items().len(), index.entry_count()),
        (ITEMS, 2 * ITEMS)
    );
    for (i, item) in index.items().iter().enumerate() {
        assert_eq!(
            &reader.read_head(&keys, item).unwrap()[..],
            format!("head {i}").as_bytes()
        );
        assert_eq!(&reader.read_secret(&keys, item).unwrap()[..], secret(i));
    }
    let site: Vec<u32> = index
        .lookup_by_key(&keys, b"site-7.example")
        .iter()
        .map(|item| item.item)
        .collect();
    assert_eq!(site, [7, 307, 607, 907]);
    assert!(index.lookup_by_key(&keys, b"item-1000").is_empty());

    // The viewer gets only the pack-scoped keys.
    let viewer = PackKeys::from_bytes(*keys.pack_key(), *keys.index_key());
    let item = viewer_lookup(&reader, &viewer, b"item-3");
    assert_eq!(&reader.read_secret(&viewer, &item).unwrap()[..], secret(3));
}

fn viewer_lookup(
    reader: &PackReader<crate::blocks::MemReader>,
    keys: &PackKeys,
    key: &[u8],
) -> crate::pack::ItemRef {
    reader.read_index(keys).unwrap().lookup_by_key(keys, key)[0]
}

#[test]
fn records_are_bound_to_their_pack_position_and_tag() {
    let (blocks, summary) = written();
    let reader = PackReader::open(&blocks, NAME).unwrap();
    let keys = keys_for(&reader);
    let item = reader
        .read_index(&keys)
        .unwrap()
        .lookup_by_key(&keys, b"item-9")[0];
    let record = blocks
        .read_range(NAME, item.secret.off, item.secret.len as usize)
        .unwrap();
    let id = summary.id;
    assert_eq!(
        &open_record(NAME, &keys, &id, item.secret.ix, Tag::Secret, &record).unwrap()[..],
        secret(9)
    );

    let other_id = PackId([0xee; 32]);
    let other_keys = PackKeys::derive(&[5; 32], &VAULT, &EPOCH, &id);
    let wrong = [
        open_record(NAME, &keys, &other_id, item.secret.ix, Tag::Secret, &record),
        open_record(NAME, &keys, &id, item.secret.ix + 2, Tag::Secret, &record),
        open_record(NAME, &keys, &id, item.head.ix, Tag::Secret, &record),
        open_record(NAME, &keys, &id, item.secret.ix, Tag::Head, &record),
        open_record(NAME, &other_keys, &id, item.secret.ix, Tag::Secret, &record),
        open_record(
            NAME,
            &PackKeys::derive(&EPOCH_KEY, &VAULT, &EPOCH, &other_id),
            &id,
            item.secret.ix,
            Tag::Secret,
            &record,
        ),
    ];
    for (case, result) in wrong.into_iter().enumerate() {
        assert!(matches!(result, Err(Error::Decrypt)), "case {case}");
    }

    // Through the reader: a swapped ix, or another epoch key.
    let swapped = RecordRef {
        ix: item.secret.ix + 2,
        ..item.secret
    };
    assert!(matches!(
        reader.read_record(&keys, &swapped, Tag::Secret),
        Err(Error::Decrypt)
    ));
    assert!(matches!(
        reader.read_index(&other_keys),
        Err(Error::Decrypt)
    ));
    let outside = RecordRef {
        off: summary.len - 10,
        ..item.secret
    };
    assert!(matches!(
        reader.read_record(&keys, &outside, Tag::Secret),
        Err(Error::CorruptPack { .. })
    ));
}

#[test]
fn the_trailer_catches_any_flipped_byte() {
    let (blocks, summary) = written();
    for at in [
        0,
        9,
        HEADER_LEN,
        HEADER_LEN + 40,
        summary.header.index_off as usize + 50,
        summary.len as usize - 33,
        summary.len as usize - 1,
    ] {
        let copy = blocks.reboot();
        copy.flip_bit(NAME, at, 1);
        let verified = PackReader::open(&copy, NAME).and_then(|reader| reader.verify_trailer());
        assert!(
            matches!(verified, Err(Error::CorruptPack { .. })),
            "flip at {at}"
        );
    }
    // A header changed to still parse changes the PackId, so nothing opens.
    let copy = blocks.reboot();
    copy.flip_bit(NAME, 8 + 32 + 32, 0);
    let reader = PackReader::open(&copy, NAME).unwrap();
    assert_ne!(reader.id(), summary.id);
    let keys = PackKeys::derive(&EPOCH_KEY, &VAULT, &EPOCH, &summary.id);
    assert!(matches!(reader.read_meta(&keys), Err(Error::Decrypt)));
}

#[test]
fn truncated_packs_never_open_as_valid() {
    let (blocks, summary) = written();
    let bytes = blocks.file(NAME).unwrap();
    for cut in [
        0,
        10,
        HEADER_LEN,
        HEADER_LEN + 100,
        bytes.len() / 2,
        bytes.len() - 1,
    ] {
        let copy = MemBlocks::new();
        copy.put_raw(NAME, &bytes[..cut]);
        let verified = PackReader::open(&copy, NAME).and_then(|reader| reader.verify_trailer());
        assert!(verified.is_err(), "cut at {cut}");
    }
    assert_eq!(bytes.len() as u64, summary.len);
}

#[test]
fn empty_packs_work_and_items_need_a_key() {
    let mut input = big_input();
    input.items.clear();
    let blocks = MemBlocks::new();
    pack::write(&blocks, NAME, &input, &EPOCH_KEY).unwrap();
    let reader = PackReader::open(&blocks, NAME).unwrap();
    reader.verify_trailer().unwrap();
    let keys = keys_for(&reader);
    assert!(reader.read_index(&keys).unwrap().items().is_empty());

    input.items.push(PackItem {
        keys: Vec::new(),
        head: Zeroizing::default(),
        secret: Zeroizing::default(),
    });
    assert!(matches!(
        pack::encode(&input, &EPOCH_KEY),
        Err(Error::InvalidInput(_))
    ));
    // Packs are create-new only.
    input.items.clear();
    assert!(matches!(
        pack::write(&blocks, NAME, &input, &EPOCH_KEY),
        Err(Error::AlreadyExists { .. })
    ));
}
