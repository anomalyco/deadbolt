use std::collections::BTreeSet;

use zeroize::Zeroizing;

use crate::blocks::BlockReader;
use crate::{PackInput, PackItem, PackKeys, PackReader};

mod compaction;
#[cfg(not(target_arch = "wasm32"))]
mod fs;
mod local;
mod log;
mod objects;
mod pack;

pub(crate) const VAULT: [u8; 32] = [1; 32];
pub(crate) const AUTHOR: [u8; 32] = [2; 32];
pub(crate) const EPOCH: [u8; 32] = [3; 32];
pub(crate) const EPOCH_KEY: [u8; 32] = [4; 32];

/// A distinct frame of varying length.
pub(crate) fn frame(i: usize) -> Vec<u8> {
    let mut out = format!("frame-{i:05}:").into_bytes();
    out.extend((0..i % 37).map(|j| (i * 31 + j) as u8));
    out
}

pub(crate) fn head_of(frame: &[u8]) -> Vec<u8> {
    [b"head:".as_slice(), frame].concat()
}

pub(crate) fn secret_of(frame: &[u8]) -> Vec<u8> {
    [b"secret:".as_slice(), frame].concat()
}

/// A pack covering `frames`: Meta lists them, and each is an item filed
/// under its own bytes.
pub(crate) fn pack_input(frames: &[Vec<u8>]) -> PackInput {
    let mut meta = Vec::new();
    for frame in frames {
        meta.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        meta.extend_from_slice(frame);
    }
    PackInput {
        vault: VAULT,
        author: AUTHOR,
        seq: frames.len() as u64,
        epoch: EPOCH,
        generation: 0,
        meta: Zeroizing::new(meta),
        items: frames
            .iter()
            .map(|frame| PackItem {
                keys: vec![frame.clone()],
                head: Zeroizing::new(head_of(frame)),
                secret: Zeroizing::new(secret_of(frame)),
            })
            .collect(),
    }
}

pub(crate) fn keys_for<R: BlockReader>(pack: &PackReader<R>) -> PackKeys {
    PackKeys::derive(&EPOCH_KEY, &VAULT, &EPOCH, &pack.id())
}

fn meta_frames(meta: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = meta;
    while let Some((len, tail)) = rest.split_first_chunk::<4>() {
        let len = u32::from_le_bytes(*len) as usize;
        out.push(tail[..len].to_vec());
        rest = &tail[len..];
    }
    out
}

/// The frames a directory holds: the pack's plus every WAL record.
pub(crate) fn logical<R: BlockReader>(
    pack: Option<&PackReader<R>>,
    wal: &[Vec<u8>],
) -> BTreeSet<Vec<u8>> {
    let mut out: BTreeSet<Vec<u8>> = wal.iter().cloned().collect();
    if let Some(pack) = pack {
        out.extend(meta_frames(&pack.read_meta(&keys_for(pack)).unwrap()));
    }
    out
}
