//! A small multi-device data-plane simulator: devices write frames with honest delta
//! clocks, sync knowledge pairwise, go offline, and compact into checkpoints.

use std::collections::{BTreeMap, BTreeSet};

use crate::id::{DeviceId, ItemId};

use super::super::*;

pub(super) const K_MAC: [u8; 32] = [0x5a; 32];
pub(super) const DAY_MS: u64 = 24 * 60 * 60 * 1000;

pub(super) fn dev(i: usize) -> DeviceId {
    DeviceId::from_bytes([u8::try_from(i).unwrap() + 1; 32])
}

pub(super) fn item(i: u8) -> ItemId {
    ItemId::from_bytes([i + 1; 16])
}

pub(super) fn root() -> DeviceId {
    DeviceId::from_bytes([0xee; 32])
}

/// Device `i` was added by device `i - 1`; device 0 by the recovery root.
pub(super) fn adders(n: usize) -> BTreeMap<DeviceId, DeviceId> {
    (0..n)
        .map(|i| (dev(i), if i == 0 { root() } else { dev(i - 1) }))
        .collect()
}

/// Membership with every device active except `removed`.
pub(super) fn membership(n: usize, removed: Option<(usize, Option<u64>)>) -> ResolvedMembership {
    let mut m = ResolvedMembership::default();
    m.devices = (0..n).map(dev).collect();
    // The sim seals every frame under `EpochId::ZERO`, an authorized epoch.
    m.authorized_frames.insert(EpochId::ZERO.as_frame_id());
    m.active_recovery = Some(root());
    if let Some((victim, last_seen)) = removed {
        m.devices.remove(&dev(victim));
        m.removed.insert(dev(victim), last_seen);
    }
    m
}

/// One random op, decoded from small integers.
pub(super) fn op(author: usize, n: usize, spec: (u8, u8, u8, u8, u8)) -> DataOp {
    let (kind, it, field, value, target) = spec;
    let field = ["user", "pass", "url"][usize::from(field % 3)].to_string();
    let it = item(it % 4);
    match kind % 10 {
        0..=2 => DataOp::SetField {
            item: it,
            field,
            value: FieldValue {
                kind: "text".into(),
                value: format!("v{value}-{author}"),
            },
        },
        3 => DataOp::ClearField { item: it, field },
        4 => DataOp::PutItem {
            item: it,
            kind: ["login", "note"][usize::from(value % 2)].into(),
        },
        5 => DataOp::DeleteItem { item: it },
        6 => DataOp::RestoreItem { item: it },
        7 => DataOp::VaultMeta {
            name: format!("vault {value}"),
        },
        8 => DataOp::DeviceCard {
            device: dev(usize::from(target) % n),
            net_pk: NetPublic::from_bytes([value; 32]),
            label: format!("card {value} by {author}"),
        },
        _ => DataOp::Dispute {
            checkpoint: FrameId::from_bytes([value; 32]),
            expected_state_mac: [target; 32],
        },
    }
}

/// Stand-in for `deadbolt-pack` sealing a plaintext pack into its encrypted `DBPK` file: any
/// bytes that differ from the plaintext prove the checkpoint commits to the sealed file.
pub(super) fn sealed(plain: &[u8]) -> Vec<u8> {
    [b"DBPK".as_slice(), blake3::hash(plain).as_bytes(), plain].concat()
}

/// Synthetic frame id over the author, position and encoded body.
fn synthetic_id(author: &DeviceId, seq: u64, prev: &FrameId, body: &[u8]) -> FrameId {
    let mut h = blake3::Hasher::new();
    h.update(author.as_bytes());
    h.update(&seq.to_be_bytes());
    h.update(prev.as_bytes());
    h.update(body);
    FrameId::from_bytes(h.finalize().into())
}

pub(super) struct Sim {
    pub n: usize,
    pub frames: Vec<DataFrame>,
    pub clocks: Vec<VectorClock>,
    pub knows: Vec<BTreeSet<usize>>,
    pub last: Vec<Option<usize>>,
    pub offline: BTreeSet<usize>,
    pub now_ms: u64,
}

impl Sim {
    pub fn new(n: usize) -> Self {
        Self {
            n,
            frames: Vec::new(),
            clocks: Vec::new(),
            knows: vec![BTreeSet::new(); n],
            last: vec![None; n],
            offline: BTreeSet::new(),
            now_ms: 1_700_000_000_000,
        }
    }

    /// Rule E7: what device `d` may claim it has seen.
    pub fn knowledge(&self, d: usize) -> VectorClock {
        honest_clock(self.knows[d].iter().map(|&i| {
            let f = &self.frames[i];
            (f.author, f.seq, true)
        }))
    }

    fn next_pos(&self, d: usize) -> (u64, FrameId, VectorClock) {
        match self.last[d] {
            None => (0, FrameId::ZERO, VectorClock::new()),
            Some(i) => (
                self.frames[i].seq + 1,
                self.frames[i].id,
                self.clocks[i].clone(),
            ),
        }
    }

    fn push(&mut self, d: usize, frame: DataFrame, clock: VectorClock) -> usize {
        let i = self.frames.len();
        self.frames.push(frame);
        self.clocks.push(clock);
        self.knows[d].insert(i);
        self.last[d] = Some(i);
        i
    }

    /// Device `d` writes one data frame with an honest, minimal `dclock`.
    pub fn write(&mut self, d: usize, ops: Vec<DataOp>) -> usize {
        self.now_ms += 3_600_000;
        let author = dev(d);
        let (seq, prev, prev_clock) = self.next_pos(d);
        let known = self.knowledge(d);
        let payload = DataPayload {
            mheads: Vec::new(),
            dclock: next_dclock(&prev_clock, &known, &author),
            timestamp_ms: self.now_ms,
            ops,
        };
        let bytes = payload.encode().unwrap();
        assert_eq!(DataPayload::decode(&bytes).unwrap(), payload);
        let frame = DataFrame {
            id: synthetic_id(&author, seq, &prev, &bytes),
            author,
            seq,
            prev,
            epoch: EpochId::ZERO,
            body: DataBody::Data(payload),
        };
        let clock = frame.clock_after(&prev_clock);
        let mut expected = known;
        expected.observe(author, seq);
        assert_eq!(
            clock, expected,
            "dclock must rebuild the writer's full clock"
        );
        self.push(d, frame, clock)
    }

    /// Pairwise sync; offline devices sync with no one.
    pub fn sync(&mut self, a: usize, b: usize) {
        if a == b || self.offline.contains(&a) || self.offline.contains(&b) {
            return;
        }
        let union: BTreeSet<usize> = self.knows[a].union(&self.knows[b]).copied().collect();
        self.knows[a] = union.clone();
        self.knows[b] = union;
    }

    /// Device `d` compacts its whole view and appends the `Checkpoint` frame.
    pub fn checkpoint(
        &mut self,
        d: usize,
        ctx: &FoldContext<'_>,
        base: Option<&Pack>,
    ) -> (Pack, Vec<u8>, usize) {
        self.checkpoint_cut(d, ctx, base, None)
    }

    /// Like `checkpoint`, but author `a`'s frames at or above `cut[a]` stay out of the
    /// compaction: an arbitrary frontier that need not be causally closed.
    pub fn checkpoint_cut(
        &mut self,
        d: usize,
        ctx: &FoldContext<'_>,
        base: Option<&Pack>,
        cut: Option<&[u64]>,
    ) -> (Pack, Vec<u8>, usize) {
        self.now_ms += 3_600_000;
        let authors: Vec<_> = (0..self.n).map(dev).collect();
        let view: Vec<&DataFrame> = self.knows[d]
            .iter()
            .map(|&i| &self.frames[i])
            .filter(|f| {
                let a = authors.iter().position(|x| *x == f.author).unwrap();
                cut.is_none_or(|c| f.seq < c[a])
            })
            .collect();
        let pack = compact(ctx, base, view).unwrap();
        let bytes = pack.encode().unwrap();
        let commitment = PackCommitment::of(&sealed(&bytes));
        let payload = build_checkpoint(&K_MAC, &pack, commitment, Vec::new(), self.now_ms).unwrap();
        assert_ne!(payload.pack_hash, *blake3::hash(&bytes).as_bytes());
        assert_eq!(Pack::decode(&bytes).unwrap(), pack, "pack must round-trip");
        let encoded = payload.encode().unwrap();
        assert_eq!(CheckpointPayload::decode(&encoded).unwrap(), payload);
        let author = dev(d);
        let (seq, prev, prev_clock) = self.next_pos(d);
        let frame = DataFrame {
            id: synthetic_id(&author, seq, &prev, &encoded),
            author,
            seq,
            prev,
            epoch: EpochId::ZERO,
            body: DataBody::Checkpoint(payload),
        };
        let clock = frame.clock_after(&prev_clock);
        let i = self.push(d, frame, clock);
        (pack, bytes, i)
    }

    /// Every frame, delivered in a seeded random order.
    pub fn shuffled(&self, seed: u64) -> Vec<&DataFrame> {
        let refs: Vec<&DataFrame> = self.frames.iter().collect();
        super::model::shuffled(&refs, seed)
    }
}
