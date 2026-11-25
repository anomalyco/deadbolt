use crate::objects::{get_blob, list_outbox, put_blob, put_outbox};
use crate::{Blocks, Error, MemBlocks};

#[test]
fn blobs_are_content_addressed_and_checked() {
    let blocks = MemBlocks::new();
    let hash = put_blob(&blocks, b"attachment").unwrap();
    assert_eq!(hash, <[u8; 32]>::from(blake3::hash(b"attachment")));
    assert_eq!(
        put_blob(&blocks, b"attachment").unwrap(),
        hash,
        "idempotent"
    );
    assert_eq!(get_blob(&blocks, &hash).unwrap(), b"attachment");
    let name = crate::names::blob(&hash);
    assert_eq!(
        blocks.list_prefix("blob/").unwrap(),
        std::slice::from_ref(&name)
    );

    blocks.flip_bit(&name, 0, 0);
    assert!(matches!(
        get_blob(&blocks, &hash),
        Err(Error::CorruptBlob { .. })
    ));
    // A torn or damaged copy is replaced by the next put.
    blocks.put_raw(&name, b"attach");
    assert_eq!(put_blob(&blocks, b"attachment").unwrap(), hash);
    assert_eq!(get_blob(&blocks, &hash).unwrap(), b"attachment");
}

#[test]
fn the_outbox_takes_fresh_names() {
    let blocks = MemBlocks::new();
    let a = put_outbox(&blocks, b"sealed a").unwrap();
    let b = put_outbox(&blocks, b"sealed b").unwrap();
    assert_ne!(a, b);
    assert!(a.starts_with("outbox/") && a.ends_with(".wrap"));
    let mut both = vec![a.clone(), b.clone()];
    both.sort();
    assert_eq!(list_outbox(&blocks).unwrap(), both);
    assert_eq!(blocks.read_all(&a).unwrap(), b"sealed a");
    assert!(blocks.delete(&a).unwrap());
    assert_eq!(list_outbox(&blocks).unwrap(), [b]);
}

#[test]
fn names_are_checked() {
    let blocks = MemBlocks::new();
    for bad in [
        "", "../x", "/x", "a/b/c", ".hidden", "blob/.x", "a\\b", "a b", "blob/",
    ] {
        assert!(
            matches!(blocks.create_new(bad, b""), Err(Error::InvalidName { .. })),
            "{bad:?}"
        );
    }
    assert!(blocks.list_prefix("../").is_err());
    assert_eq!(
        crate::names::parse_numbered("gen-12.pack", "gen-", ".pack"),
        Some(12)
    );
    for bad in ["gen-.pack", "gen-012.pack", "gen-1x.pack", "gen-1.pack.tmp"] {
        assert_eq!(
            crate::names::parse_numbered(bad, "gen-", ".pack"),
            None,
            "{bad}"
        );
    }
}
