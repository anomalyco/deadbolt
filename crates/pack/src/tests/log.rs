use crate::log::{self, MAX_RECORD, encode};
use crate::{Blocks, Error, MemBlocks};

const NAME: &str = "wal-0.log";

fn records() -> Vec<Vec<u8>> {
    vec![
        b"first".to_vec(),
        vec![0xab; 300],
        Vec::new(),
        b"the last record".to_vec(),
    ]
}

fn framed() -> (Vec<u8>, Vec<usize>) {
    let mut bytes = Vec::new();
    let mut ends = Vec::new();
    for record in records() {
        bytes.extend(encode(&record).unwrap());
        ends.push(bytes.len());
    }
    (bytes, ends)
}

#[test]
fn truncation_at_every_byte_recovers_exactly_the_committed_prefix() {
    let (full, ends) = framed();
    let last_start = ends[ends.len() - 2];
    assert!(full.len() - last_start > 12);
    for cut in 0..=full.len() {
        let committed = ends.iter().filter(|&&end| end <= cut).count();
        let prefix_len = if committed == 0 {
            0
        } else {
            ends[committed - 1]
        };
        let expected = &records()[..committed];
        let blocks = MemBlocks::new();
        blocks.put_raw(NAME, &full[..cut]);

        // A lock-free reader sees the prefix and leaves the file alone.
        assert_eq!(
            log::read(&blocks, NAME).unwrap(),
            expected,
            "read at cut {cut}"
        );
        assert_eq!(blocks.file(NAME).unwrap().len(), cut);

        // The writer cuts back to the last committed record, no further.
        assert_eq!(
            log::recover(&blocks, NAME).unwrap(),
            expected,
            "recover at cut {cut}"
        );
        assert_eq!(
            blocks.file(NAME).unwrap(),
            full[..prefix_len],
            "file at cut {cut}"
        );

        // The next append starts on a record boundary.
        log::append(&blocks, NAME, b"after").unwrap();
        let mut after = expected.to_vec();
        after.push(b"after".to_vec());
        assert_eq!(log::recover(&blocks, NAME).unwrap(), after);
    }
}

#[test]
fn damage_to_the_last_record_is_a_torn_append() {
    let (full, ends) = framed();
    let last_start = ends[ends.len() - 2];
    for at in last_start..full.len() {
        let blocks = MemBlocks::new();
        blocks.put_raw(NAME, &full);
        blocks.flip_bit(NAME, at, 3);
        assert_eq!(
            log::recover(&blocks, NAME).unwrap(),
            records()[..3],
            "flip at {at}"
        );
        assert_eq!(blocks.file(NAME).unwrap(), full[..last_start]);
    }
}

#[test]
fn damage_before_a_valid_record_is_corruption_never_truncated() {
    let (full, ends) = framed();
    let starts: Vec<usize> = std::iter::once(0).chain(ends.iter().copied()).collect();
    for record in 0..records().len() - 1 {
        for at in starts[record]..ends[record] {
            for bit in [0, 7] {
                let blocks = MemBlocks::new();
                blocks.put_raw(NAME, &full);
                blocks.flip_bit(NAME, at, bit);
                let damaged = blocks.file(NAME).unwrap();
                for result in [log::recover(&blocks, NAME), log::read(&blocks, NAME)] {
                    match result {
                        Err(Error::CorruptLog { file, offset }) => {
                            assert_eq!(file, NAME);
                            assert_eq!(offset, starts[record] as u64, "flip at {at} bit {bit}");
                        }
                        other => panic!("flip at {at} bit {bit}: {other:?}"),
                    }
                }
                assert_eq!(
                    blocks.file(NAME).unwrap(),
                    damaged,
                    "the file is left for quarantine"
                );
            }
        }
    }
}

#[test]
fn length_prefixes_are_bounded() {
    let too_big = vec![0; MAX_RECORD + 1];
    assert!(matches!(
        encode(&too_big),
        Err(Error::RecordTooLarge { .. })
    ));
    assert!(encode(&too_big[..MAX_RECORD]).is_ok());

    // A huge length at the end is a torn tail; before a valid record it's corruption.
    let (full, _) = framed();
    let mut tail = full.clone();
    tail.extend_from_slice(&u32::MAX.to_le_bytes());
    tail.extend_from_slice(b"junk");
    let blocks = MemBlocks::new();
    blocks.put_raw(NAME, &tail);
    assert_eq!(log::recover(&blocks, NAME).unwrap(), records());
    assert_eq!(blocks.file(NAME).unwrap(), full);

    let mut middle = u32::MAX.to_le_bytes().to_vec();
    middle.extend_from_slice(&full);
    blocks.put_raw(NAME, &middle);
    assert!(matches!(
        log::recover(&blocks, NAME),
        Err(Error::CorruptLog { offset: 0, .. })
    ));
}

#[test]
fn a_missing_log_is_empty_and_append_creates_it() {
    let blocks = MemBlocks::new();
    assert!(log::recover(&blocks, NAME).unwrap().is_empty());
    assert!(log::read(&blocks, NAME).unwrap().is_empty());
    assert_eq!(log::append(&blocks, NAME, b"one").unwrap(), 0);
    assert_eq!(log::append(&blocks, NAME, b"two").unwrap(), 15);
    assert_eq!(
        log::read(&blocks, NAME).unwrap(),
        [b"one".to_vec(), b"two".to_vec()]
    );
    assert_eq!(blocks.read_all(NAME).unwrap()[..4], 3u32.to_le_bytes());
}
