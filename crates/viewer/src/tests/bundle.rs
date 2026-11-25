use deadbolt_pack::{MemBlocks, PackKeys};

use super::{EXPIRES, NOW, bundle_for, epoch_key, secret, write_pack};
use crate::bundle::BUNDLE_LEN;
use crate::{ViewerError, ViewerKeyBundle};

#[test]
fn the_bundle_holds_exactly_the_packs_keys() {
    let blocks = MemBlocks::new();
    let summary = write_pack(&blocks, 3, 1);
    let bundle = bundle_for(&summary);
    // The same keys deadbolt-pack seals the pack under.
    let keys = PackKeys::derive(
        epoch_key().as_bytes(),
        &summary.header.vault,
        &summary.header.epoch,
        &summary.id,
    );
    assert_eq!(*bundle.k_pack, *keys.pack_key());
    assert_eq!(*bundle.k_ix, *keys.index_key());
    assert_eq!(bundle.pack_id, summary.id.0);
    assert_ne!(*bundle.k_pack, *epoch_key().as_bytes());
    assert_ne!(*bundle.k_ix, *epoch_key().as_bytes());

    let bytes = bundle.encode();
    assert_eq!(bytes.len(), BUNDLE_LEN);
    assert_eq!(BUNDLE_LEN, 173);
    assert_eq!(ViewerKeyBundle::decode(&bytes).unwrap(), bundle);
    assert!(!bundle.is_expired(NOW));
    assert!(bundle.is_expired(EXPIRES));
}

#[test]
fn malformed_bundles_are_refused() {
    let blocks = MemBlocks::new();
    let bytes = bundle_for(&write_pack(&blocks, 1, 1)).encode();
    let mut cases = vec![
        Vec::new(),
        bytes[..BUNDLE_LEN - 1].to_vec(),
        [&bytes[..], &[0]].concat(),
    ];
    for at in [0, 4] {
        let mut bad = bytes.to_vec();
        bad[at] ^= 1;
        cases.push(bad);
    }
    for (case, bad) in cases.iter().enumerate() {
        assert_eq!(
            ViewerKeyBundle::decode(bad),
            Err(ViewerError::InvalidBundle),
            "case {case}"
        );
    }
}

#[test]
fn debug_never_shows_a_key_or_a_secret() {
    let blocks = MemBlocks::new();
    let bundle = bundle_for(&write_pack(&blocks, 1, 1));
    let shown = format!("{bundle:?}");
    let k_pack = deadbolt_pack::names::hex(&*bundle.k_pack);
    let k_ix = deadbolt_pack::names::hex(&*bundle.k_ix);
    assert!(
        !shown.contains(&k_pack) && !shown.contains(&k_ix),
        "{shown}"
    );
    assert!(shown.contains("expires_unix"));

    let secret = secret(30);
    let shown = format!("{secret:?}");
    for value in ["pw-30", "JBSWY3DPEHPK3PXP", "pkcs8-30", "handle-30"] {
        assert!(!shown.contains(value), "{shown}");
    }
    assert!(shown.contains("cred-30") && shown.contains("<redacted>"));
}
