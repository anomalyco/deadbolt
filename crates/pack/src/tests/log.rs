use std::time::Instant;

use crate::log::{self, HEADER_LEN, MAGIC, MAX_RECORD, RECORD_OVERHEAD, encode, hash_count};
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
    assert_eq!(
        log::append(&blocks, NAME, b"two").unwrap(),
        (RECORD_OVERHEAD + 3) as u64
    );
    assert_eq!(
        log::read(&blocks, NAME).unwrap(),
        [b"one".to_vec(), b"two".to_vec()]
    );
    let bytes = blocks.read_all(NAME).unwrap();
    assert_eq!(bytes[..8], MAGIC);
    assert_eq!(bytes[8..HEADER_LEN], 3u32.to_le_bytes());
}

/// Deterministic noise.
fn noise(seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    blake3::Hasher::new()
        .update(seed)
        .finalize_xof()
        .fill(&mut out);
    out
}

/// A payload that holds whole encoded records of its own.
fn nesting_payload() -> Vec<u8> {
    let mut payload = b"outer:".to_vec();
    payload.extend(encode(b"inner one").unwrap());
    payload.extend(encode(b"inner two").unwrap());
    payload.extend_from_slice(b":outer");
    payload
}

#[test]
fn a_torn_record_holding_encoded_records_is_cut_not_corrupt() {
    let (committed, _) = framed();
    let last = encode(&nesting_payload()).unwrap();
    // Every cut, including the exact ends of the records nested inside, and
    // 40 bytes in.
    for cut in (1..last.len()).chain([40]) {
        let blocks = MemBlocks::new();
        blocks.put_raw(NAME, &[committed.as_slice(), &last[..cut]].concat());
        assert_eq!(
            log::read(&blocks, NAME).unwrap(),
            records(),
            "read at {cut}"
        );
        assert_eq!(
            log::recover(&blocks, NAME).unwrap(),
            records(),
            "recover at {cut}"
        );
        assert_eq!(blocks.file(NAME).unwrap(), committed, "cut back at {cut}");
        log::append(&blocks, NAME, &nesting_payload()).unwrap();
        let mut all = records();
        all.push(nesting_payload());
        assert_eq!(log::recover(&blocks, NAME).unwrap(), all, "reopen at {cut}");
    }
}

#[test]
fn a_bad_record_before_valid_ones_is_still_corrupt_around_nested_records() {
    let mut bytes = Vec::new();
    let mut starts = Vec::new();
    for payload in [nesting_payload(), b"middle".to_vec(), nesting_payload()] {
        starts.push(bytes.len());
        bytes.extend(encode(&payload).unwrap());
    }
    // A bit flipped in the magic, the length, the payload and the check of
    // the first and second records.
    for record in 0..2 {
        let end = starts[record + 1];
        for at in [
            starts[record],
            starts[record] + 9,
            starts[record] + 20,
            end - 1,
        ] {
            let blocks = MemBlocks::new();
            blocks.put_raw(NAME, &bytes);
            blocks.flip_bit(NAME, at, 0);
            assert!(
                matches!(
                    log::recover(&blocks, NAME),
                    Err(Error::CorruptLog { offset, .. }) if offset == starts[record] as u64
                ),
                "flip at {at}"
            );
            assert_eq!(blocks.file(NAME).unwrap().len(), bytes.len());
        }
    }
}

#[test]
fn a_large_torn_tail_scans_in_linear_time() {
    let (committed, _) = framed();
    let big = encode(&noise(b"torn", 1 << 20)).unwrap();
    // Payloads packed with encoded records, so every magic match is a
    // plausible record start.
    let mut packed = Vec::new();
    while packed.len() < 1 << 20 {
        packed.extend(encode(&noise(&packed.len().to_le_bytes(), 64)).unwrap());
    }
    let nested = encode(&packed).unwrap();
    let tails: [(&str, Vec<u8>); 4] = [
        ("torn 1 MiB record", big[..big.len() - 1].to_vec()),
        (
            "torn record of records",
            nested[..nested.len() / 2].to_vec(),
        ),
        ("1 MiB of noise", noise(b"garbage", 1 << 20)),
        // A bad header that fits, then a megabyte of records whose chain
        // breaks just before the end: the search must stay bounded.
        ("records behind a bad header", {
            let mut tail = vec![0xee; RECORD_OVERHEAD];
            tail.extend_from_slice(&packed[..packed.len() - 1]);
            tail
        }),
    ];
    for (case, tail) in tails {
        let bytes = [committed.as_slice(), &tail].concat();
        hash_count::take();
        let started = Instant::now();
        let scan = log::scan(NAME, &bytes);
        let elapsed = started.elapsed();
        let hashed = hash_count::take();
        assert!(
            hashed <= committed.len() + 4 * bytes.len(),
            "{case}: hashed {hashed} bytes"
        );
        if case == "records behind a bad header" {
            assert!(matches!(scan, Err(Error::CorruptLog { .. })), "{case}");
        } else {
            let scan = scan.unwrap();
            assert_eq!(
                (scan.records, scan.valid_len, scan.torn),
                (records(), committed.len() as u64, true),
                "{case}"
            );
            assert!(hashed < committed.len() + 4096, "{case}: hashed {hashed}");
        }
        assert!(
            elapsed.as_millis() < 5 || cfg!(debug_assertions) && elapsed.as_millis() < 500,
            "{case}: {elapsed:?}"
        );
    }
}
