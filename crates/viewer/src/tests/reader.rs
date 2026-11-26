use std::time::{Duration, Instant};

use deadbolt_pack::blocks::ReadOp;
use deadbolt_pack::pack::HEADER_LEN;
use deadbolt_pack::{FsBlocks, MemBlocks, PackReader};
use zeroize::Zeroizing;

use super::{NOW, VAULT, bundle_for, core_pack, head, item_id, password, write_pack};
use crate::{PackViewer, ViewerError};

const ITEMS: usize = 5_000;

#[test]
fn a_lookup_and_fill_read_only_the_target_head_and_secret() {
    let blocks = MemBlocks::new();
    let summary = write_pack(&blocks, ITEMS, 1);
    let bundle = bundle_for(&summary);
    let name = "gen-1.pack".to_owned();

    let viewer = PackViewer::open(&blocks, &bundle, NOW).unwrap();
    assert_eq!((viewer.item_count(), viewer.generation()), (ITEMS, 1));
    let hits = viewer
        .lookup_site("https://login.site-4321.com/signin")
        .unwrap();
    assert_eq!(hits, [head(4321)]);
    let secret = viewer.fill_secret(&hits[0].item_id).unwrap();
    assert_eq!(
        secret.password.as_deref().map(String::as_str),
        Some(&*password(4321))
    );

    let index = blocks.take_reads();
    let reader = PackReader::open(&blocks, &name).unwrap();
    let keys = bundle.pack_keys();
    let item = reader
        .read_index(&keys)
        .unwrap()
        .lookup_by_key(&keys, &crate::site_key("site-4321.com"))[0];
    blocks.take_reads();
    let read = |offset, len: u32| ReadOp {
        name: name.clone(),
        offset,
        len: u64::from(len),
    };
    let header = summary.header;
    assert_eq!(
        index,
        [
            read(0, HEADER_LEN as u32),
            read(header.index_off, header.index_len),
            read(item.head.off, item.head.len),
            read(item.head.off, item.head.len),
            read(item.secret.off, item.secret.len),
        ]
    );
    let touched: u64 = index.iter().map(|op| op.len).sum();
    eprintln!(
        "5k-item pack: {} B on disk, index record {} B, a fill read {touched} B \
         (head {} B, secret {} B)",
        summary.len, header.index_len, item.head.len, item.secret.len
    );
    // The index is 40 B per key, and each item has an id key and a site key
    // (a tenth an rp id key too); everything else read is one item.
    let past_index = touched - u64::from(header.index_len) - HEADER_LEN as u64;
    assert_eq!(
        past_index,
        2 * u64::from(item.head.len) + u64::from(item.secret.len)
    );
    assert!(touched < summary.len / 4);
}

#[test]
fn a_lookup_and_fill_on_a_5k_item_pack_on_disk_is_fast() {
    let dir = tempfile::tempdir().unwrap();
    let blocks = FsBlocks::open(dir.path()).unwrap();
    let bundle = bundle_for(&write_pack(&blocks, ITEMS, 1));

    let started = Instant::now();
    let viewer = PackViewer::open_dir(dir.path(), &bundle, NOW).unwrap();
    let opened = started.elapsed();

    let mut best = Duration::MAX;
    for i in [17, 2_500, 4_999] {
        let started = Instant::now();
        let hits = viewer.lookup_site(&format!("login.site-{i}.com")).unwrap();
        let secret = viewer.fill_secret(&hits[0].item_id).unwrap();
        best = best.min(started.elapsed());
        assert_eq!(secret.item_id, item_id(i));
    }
    eprintln!("5k-item pack on disk: open + index {opened:?}, lookup + fill {best:?}");
    assert!(
        best < Duration::from_millis(2),
        "lookup + fill took {best:?}"
    );
}

#[test]
fn lookups_find_by_site_rp_id_and_item_id() {
    let blocks = MemBlocks::new();
    let bundle = bundle_for(&write_pack(&blocks, 50, 1));
    let viewer = PackViewer::open(&blocks, &bundle, NOW).unwrap();
    // A bare domain, another subdomain, a trailing dot: the same site.
    for query in [
        "site-20.com",
        "https://www.site-20.com/x",
        "login.site-20.com.",
    ] {
        assert_eq!(viewer.lookup_site(query).unwrap(), [head(20)], "{query}");
    }
    assert_eq!(viewer.lookup_rp("SITE-20.com").unwrap(), [head(20)]);
    assert!(viewer.lookup_rp("site-21.com").unwrap().is_empty());
    assert!(viewer.lookup_site("site-99.com").unwrap().is_empty());
    assert_eq!(viewer.lookup_item(&item_id(7)).unwrap(), Some(head(7)));
    assert_eq!(viewer.lookup_item(&item_id(70)).unwrap(), None);
    assert_eq!(
        viewer.fill_secret(&item_id(70)).unwrap_err(),
        ViewerError::NotFound
    );
    assert!(matches!(
        viewer.fill_secret("not hex"),
        Err(ViewerError::InvalidInput { .. })
    ));

    let secret = viewer.fill_secret(&item_id(30)).unwrap();
    let code = secret.totp_code(NOW).unwrap().unwrap();
    assert_eq!(code.len(), 6);
    assert_eq!(secret.passkey.as_ref().unwrap().user_handle, "handle-30");
    assert_eq!(
        viewer.fill_secret(&item_id(31)).unwrap().totp_code(NOW),
        Ok(None)
    );
}

#[test]
fn an_expired_bundle_is_refused_before_any_read() {
    let blocks = MemBlocks::new();
    let mut bundle = bundle_for(&write_pack(&blocks, 10, 1));
    bundle.expires_unix = NOW;
    blocks.take_reads();
    assert!(matches!(
        PackViewer::open(&blocks, &bundle, NOW),
        Err(ViewerError::Expired { expires_unix: NOW })
    ));
    assert!(blocks.take_reads().is_empty());
    assert!(matches!(
        PackViewer::open_dir(std::path::Path::new("/nonexistent"), &bundle, NOW),
        Err(ViewerError::Expired { .. })
    ));
}

#[test]
fn a_bundle_opens_only_its_own_pack_with_its_own_keys() {
    let blocks = MemBlocks::new();
    let one = bundle_for(&write_pack(&blocks, 10, 1));
    let two = bundle_for(&write_pack(&blocks, 12, 2));
    assert_eq!(
        PackViewer::open(&blocks, &one, NOW).unwrap().generation(),
        1
    );
    assert_eq!(
        PackViewer::open(&blocks, &two, NOW).unwrap().generation(),
        2
    );

    // Another PackId: no pack on disk is it.
    let mut wrong_id = one.clone();
    wrong_id.pack_id[0] ^= 1;
    assert!(matches!(
        PackViewer::open(&blocks, &wrong_id, NOW),
        Err(ViewerError::PackNotFound)
    ));
    // Generation 2's keys don't open generation 1.
    let mut other_gen = two.clone();
    other_gen.pack_id = one.pack_id;
    assert!(matches!(
        PackViewer::open(&blocks, &other_gen, NOW),
        Err(ViewerError::WrongKey)
    ));
    // A wrong K_pack fails at the index.
    let mut wrong_pack = one.clone();
    wrong_pack.k_pack = Zeroizing::new([7; 32]);
    assert!(matches!(
        PackViewer::open(&blocks, &wrong_pack, NOW),
        Err(ViewerError::WrongKey)
    ));
    // A wrong K_ix opens the index but finds nothing under any key.
    let mut wrong_ix = one.clone();
    wrong_ix.k_ix = Zeroizing::new([7; 32]);
    let viewer = PackViewer::open(&blocks, &wrong_ix, NOW).unwrap();
    assert!(viewer.lookup_site("site-3.com").unwrap().is_empty());
    assert_eq!(viewer.lookup_item(&item_id(3)).unwrap(), None);
    assert_eq!(
        viewer.fill_secret(&item_id(3)).unwrap_err(),
        ViewerError::NotFound
    );
    // The bundle's vault must be the pack's.
    let mut other_vault = one.clone();
    other_vault.vault = [0xee; 32];
    assert!(matches!(
        PackViewer::open(&blocks, &other_vault, NOW),
        Err(ViewerError::Corrupt { .. })
    ));
    assert_eq!(
        *PackViewer::open(&blocks, &one, NOW).unwrap().vault(),
        VAULT
    );
}

#[test]
fn an_altered_record_is_refused() {
    let blocks = MemBlocks::new();
    let bundle = bundle_for(&write_pack(&blocks, 10, 1));
    let viewer = PackViewer::open(&blocks, &bundle, NOW).unwrap();
    let keys = bundle.pack_keys();
    let reader = PackReader::open(&blocks, "gen-1.pack").unwrap();
    let item = reader
        .read_index(&keys)
        .unwrap()
        .lookup_by_key(&keys, &crate::site_key("site-4.com"))[0];
    drop(viewer);

    let copy = blocks.reboot();
    copy.flip_bit("gen-1.pack", item.secret.off as usize + 40, 3);
    let viewer = PackViewer::open(&copy, &bundle, NOW).unwrap();
    assert_eq!(viewer.lookup_site("site-4.com").unwrap(), [head(4)]);
    assert_eq!(
        viewer.fill_secret(&item_id(4)).unwrap_err(),
        ViewerError::WrongKey
    );
    assert!(viewer.fill_secret(&item_id(5)).is_ok());

    let copy = blocks.reboot();
    copy.flip_bit("gen-1.pack", 8, 0);
    assert!(matches!(
        PackViewer::open(&copy, &bundle, NOW),
        Err(ViewerError::PackNotFound)
    ));
}

#[test]
fn the_app_reads_a_whole_pack_back_into_the_core_pack() {
    let blocks = MemBlocks::new();
    let bundle = bundle_for(&write_pack(&blocks, 40, 1));
    let reader = PackReader::open(&blocks, "gen-1.pack").unwrap();
    let pack = crate::read_pack(&reader, &bundle.pack_keys()).unwrap();
    assert_eq!(pack, core_pack(40));
}
