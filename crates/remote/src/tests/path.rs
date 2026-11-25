use deadbolt_core::v2::{FrameKind, LogKind};
use deadbolt_core::{DeviceId, VaultId};

use crate::path::{
    Area, PathError, RemotePath, area_prefix, stream_cursor, stream_prefix, validate_name,
    validate_prefix,
};
use crate::{MemObjStore, ObjStore};

const V: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn vault() -> VaultId {
    VaultId::from_bytes([0x11; 32])
}

fn author() -> DeviceId {
    DeviceId::from_bytes([0xaa; 32])
}

#[test]
fn every_kind_round_trips_through_its_canonical_name() {
    let v = vault();
    let cases = [
        (
            RemotePath::frame(v, FrameKind::Member, author(), 0),
            format!("{V}/m/{A}/0000000000000000"),
        ),
        (
            RemotePath::frame(v, FrameKind::Data, author(), 0x1f),
            format!("{V}/d/{A}/000000000000001f"),
        ),
        (
            RemotePath::frame(v, FrameKind::Checkpoint, author(), u64::MAX),
            format!("{V}/d/{A}/ffffffffffffffff.c"),
        ),
        (
            RemotePath::Pack {
                vault: v,
                hash: [0xab; 32],
            },
            format!("{V}/p/{}", "ab".repeat(32)),
        ),
        (
            RemotePath::Blob {
                vault: v,
                hash: [0x01; 32],
            },
            format!("{V}/b/{}", "01".repeat(32)),
        ),
        (
            RemotePath::Fraud {
                vault: v,
                hash: [0xfe; 32],
            },
            format!("{V}/x/{}", "fe".repeat(32)),
        ),
        (
            RemotePath::Send {
                vault: v,
                name: [0x5a; 16],
            },
            format!("{V}/s/{}", "5a".repeat(16)),
        ),
    ];
    for (path, name) in cases {
        assert_eq!(path.to_name(), name);
        assert_eq!(RemotePath::parse(&name), Ok(path));
        assert_eq!(path.vault(), &v);
    }
}

#[test]
fn seq_names_sort_in_seq_order_with_checkpoints_in_place() {
    let v = vault();
    let mut names: Vec<String> = [
        (3, false),
        (0x10, true),
        (2, true),
        (0x100, false),
        (1, false),
    ]
    .iter()
    .map(|&(seq, c)| {
        let kind = if c {
            FrameKind::Checkpoint
        } else {
            FrameKind::Data
        };
        RemotePath::frame(v, kind, author(), seq).to_name()
    })
    .collect();
    names.sort();
    let seqs: Vec<u64> = names
        .iter()
        .map(|n| match RemotePath::parse(n).unwrap() {
            RemotePath::Frame { seq, .. } => seq,
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(seqs, [1, 2, 3, 0x10, 0x100]);
}

#[test]
fn non_canonical_spellings_are_refused() {
    let bad = [
        String::new(),
        format!("/{V}/m/{A}/0000000000000000"),
        format!("{V}/m/{A}/../0000000000000000"),
        format!("{V}/m/{A}/./0000000000000000"),
        format!("{V}//m/{A}/0000000000000000"),
        format!("{V}/m/{A}/0000000000000000/"),
        format!("{V}/m/{}/0000000000000000", A.to_uppercase()),
        format!("{V}/m/{A}/000000000000000A"),
        format!("{V}/m/{A}/000000000000000"),
        format!("{V}/m/{A}/00000000000000000"),
        format!("{V}/m/{A}/000000000000000g"),
        format!("{V}/m/{A}/0000000000000000.c"),
        format!("{V}/d/{A}/0000000000000000.d"),
        format!("{V}/d/{A}/0000000000000000/extra"),
        format!("{V}/q/{A}"),
        format!("{V}/p/{}", "ab".repeat(31)),
        format!("{V}/s/{}", "ab".repeat(32)),
        format!("{V}/m/{A}/0000000000000000\n"),
        format!("{V}/m/{A}/00000000\u{0}0000000"),
        format!("{V}/m/{A}/0000000000000000%2e"),
        format!("{}/m/{A}/0000000000000000", &V[..62]),
    ];
    for name in bad {
        assert!(RemotePath::parse(&name).is_err(), "accepted {name:?}");
    }
}

#[test]
fn backend_name_rules_reject_escapes_before_any_request() {
    assert_eq!(validate_name(""), Err(PathError::Empty));
    assert_eq!(validate_name("/a"), Err(PathError::LeadingSlash));
    assert_eq!(validate_name("a/../b"), Err(PathError::BadSegment));
    assert_eq!(validate_name("a//b"), Err(PathError::BadSegment));
    assert_eq!(validate_name("a/"), Err(PathError::BadSegment));
    assert_eq!(validate_name("A"), Err(PathError::BadByte(b'A')));
    assert_eq!(validate_name("a\tb"), Err(PathError::BadByte(b'\t')));
    assert_eq!(validate_name("a%2f"), Err(PathError::BadByte(b'%')));
    assert_eq!(validate_name("a?b"), Err(PathError::BadByte(b'?')));
    assert_eq!(validate_name(&"a".repeat(513)), Err(PathError::TooLong));
    assert!(validate_name("a.b-c_d/e").is_ok());
    assert!(validate_prefix("").is_ok());
    assert!(validate_prefix("a/b/").is_ok());
    assert_eq!(validate_prefix("a/../"), Err(PathError::BadSegment));
}

#[test]
fn prefixes_nest() {
    let v = vault();
    assert_eq!(area_prefix(&v, Area::Fraud), format!("{V}/x/"));
    assert_eq!(
        stream_prefix(&v, LogKind::Data, &author()),
        format!("{V}/d/{A}/")
    );
    assert!(
        RemotePath::frame(v, FrameKind::Checkpoint, author(), 9)
            .to_name()
            .starts_with(&stream_prefix(&v, LogKind::Data, &author()))
    );
    assert_eq!(stream_cursor(&v, LogKind::Data, &author(), 0), None);
}

#[tokio::test]
async fn stream_cursor_lists_from_seq_including_checkpoint_spellings() {
    let v = vault();
    let store = MemObjStore::new();
    for (seq, kind) in [
        (0, FrameKind::Data),
        (1, FrameKind::Checkpoint),
        (2, FrameKind::Data),
        (3, FrameKind::Checkpoint),
    ] {
        let name = RemotePath::frame(v, kind, author(), seq).to_name();
        store.put(&name, b"x", true).await.unwrap();
    }
    let prefix = stream_prefix(&v, LogKind::Data, &author());
    for from in 0..=4u64 {
        let after = stream_cursor(&v, LogKind::Data, &author(), from);
        let listed = store.list(&prefix, after.as_deref()).await.unwrap();
        let seqs: Vec<u64> = listed
            .iter()
            .map(|n| match RemotePath::parse(n).unwrap() {
                RemotePath::Frame { seq, .. } => seq,
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(seqs, (from..4).collect::<Vec<_>>(), "from {from}");
    }
}
