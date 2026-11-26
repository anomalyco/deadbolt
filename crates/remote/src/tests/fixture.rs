//! Signed frames for the planner tests.

use deadbolt_core::v2::{
    DeviceKeys, EpochId, EpochKey, Frame, FrameId, FraudProof, RecoverySecret, build_add_frame,
    build_create_frame, resolve, sign_join_consent,
};
use deadbolt_core::{DeviceId, DeviceSecret, VaultId};

pub fn device(seed: u8) -> DeviceSecret {
    DeviceSecret::from_bytes(&[seed; 32])
}

pub fn vault() -> VaultId {
    VaultId::from_bytes([0x11; 32])
}

fn epoch() -> (EpochId, EpochKey) {
    (
        EpochId::from_bytes([0x22; 32]),
        EpochKey::from_bytes([0x33; 32]),
    )
}

/// One Data (or Checkpoint) frame; `salt` varies the plaintext, so two
/// salts at one position are a fork.
pub fn data_frame(
    sk: &DeviceSecret,
    vault: VaultId,
    seq: u64,
    prev: FrameId,
    salt: u8,
    checkpoint: bool,
) -> Frame {
    let (epoch, key) = epoch();
    let pt = [salt; 40];
    if checkpoint {
        Frame::seal_checkpoint(sk, vault, seq, prev, epoch, &key, &pt).unwrap()
    } else {
        Frame::seal_data(sk, vault, seq, prev, epoch, &key, &pt).unwrap()
    }
}

/// `n` chained Data frames from seq 0; seqs in `checkpoints` are Checkpoints.
pub fn data_chain(
    sk: &DeviceSecret,
    vault: VaultId,
    n: u64,
    salt: u8,
    checkpoints: &[u64],
) -> Vec<Frame> {
    let mut prev = FrameId::ZERO;
    (0..n)
        .map(|seq| {
            let frame = data_frame(sk, vault, seq, prev, salt, checkpoints.contains(&seq));
            prev = frame.id();
            frame
        })
        .collect()
}

/// A genesis `Create` by a recovery root, then `adds` `Add` frames: the
/// root's Member stream, seqs `0..=adds`.
pub fn genesis(adds: u8) -> (VaultId, DeviceId, Vec<Frame>) {
    let rs = RecoverySecret::from_bytes([0x44; 32]);
    let root = rs.signing_key();
    let root_id = rs.recovery_id();
    let k0 = EpochKey::from_bytes([0x55; 32]);
    let create = build_create_frame(&rs, [0x66; 32], &k0).unwrap();
    let vault = create.header().vault;
    let e0 = EpochId::from_frame_id(create.id());
    let mut frames = vec![create];
    for i in 0..adds {
        let dev = DeviceKeys::from_seed(&[0x70 + i; 32]);
        let prev = frames.last().unwrap().id();
        let add = build_add_frame(
            &root,
            vault,
            &resolve(&vault, &frames, &[]),
            u64::from(i) + 1,
            prev,
            vec![prev],
            dev.device_id(),
            dev.kem_public(),
            sign_join_consent(&dev, &vault, &root_id),
            Some((e0, &k0)),
        )
        .unwrap();
        frames.push(add);
    }
    (vault, root_id, frames)
}

/// A fraud proof: two forks of one Data position.
pub fn fraud(sk: &DeviceSecret, vault: VaultId) -> FraudProof {
    let a = data_frame(sk, vault, 0, FrameId::ZERO, 1, false);
    let b = data_frame(sk, vault, 0, FrameId::ZERO, 2, false);
    FraudProof::from_frames(&a, &b).unwrap()
}
