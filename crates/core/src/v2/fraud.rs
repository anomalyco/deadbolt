//! Keyless 482-byte `FraudProof`s for equivocation detection in `deadbolt_core::v2`.

use std::collections::BTreeMap;

use crate::id::{DeviceId, VaultId};

use super::crypto::FrameId;
use super::frame::{Frame, FrameError, FrameHeader, FrameWitness, LogKind, WITNESS_LEN};

/// Exact canonical byte length of a keyless `FraudProof` (2 × 241 bytes).
pub const FRAUD_PROOF_LEN: usize = WITNESS_LEN * 2;

/// Errors returned when constructing or verifying a `FraudProof`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FraudError {
    #[error("invalid fraud proof length {0}, expected {FRAUD_PROOF_LEN}")]
    InvalidLength(usize),
    #[error("witness error: {0}")]
    Witness(#[from] FrameError),
    #[error("witnesses belong to different vaults")]
    DifferentVault,
    #[error("witnesses have different authors")]
    DifferentAuthor,
    #[error("witnesses belong to different log streams")]
    DifferentLog,
    #[error("witnesses have different sequence numbers")]
    DifferentSeq,
    #[error("witnesses refer to the exact same frame")]
    SameFrame,
    #[error("fraud proof witnesses are not canonically ordered (id_a < id_b)")]
    NotCanonical,
}

/// Verified summary extracted from a keyless 482-byte `FraudProof`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedFraud {
    pub vault: VaultId,
    pub author: DeviceId,
    pub log: LogKind,
    pub seq: u64,
    pub id_a: FrameId,
    pub id_b: FrameId,
}

/// A 482-byte keyless proof of equivocation: two strictly verified signatures by the same
/// author for the same `(vault, log_kind, seq)` with distinct `FrameId`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FraudProof {
    a: FrameWitness,
    b: FrameWitness,
}

impl FraudProof {
    /// Builds a canonical `FraudProof` from two conflicting `FrameWitness`es.
    pub fn from_witnesses(w1: FrameWitness, w2: FrameWitness) -> Result<Self, FraudError> {
        let (h1, id1) = w1.verify()?;
        let (h2, id2) = w2.verify()?;
        validate_conflict(&h1, id1, &h2, id2)?;
        let (a, b) = if id1 < id2 { (w1, w2) } else { (w2, w1) };
        Ok(Self { a, b })
    }

    /// Builds a canonical `FraudProof` from two conflicting `Frame`s.
    pub fn from_frames(f1: &Frame, f2: &Frame) -> Result<Self, FraudError> {
        Self::from_witnesses(f1.witness(), f2.witness())
    }

    /// Encodes the proof into its exact 482-byte canonical representation.
    pub fn encode(&self) -> [u8; FRAUD_PROOF_LEN] {
        let mut out = [0u8; FRAUD_PROOF_LEN];
        out[..WITNESS_LEN].copy_from_slice(&self.a.encode());
        out[WITNESS_LEN..].copy_from_slice(&self.b.encode());
        out
    }

    /// Decodes and strictly verifies a 482-byte `FraudProof` with zero keys.
    pub fn decode(bytes: &[u8]) -> Result<Self, FraudError> {
        if bytes.len() != FRAUD_PROOF_LEN {
            return Err(FraudError::InvalidLength(bytes.len()));
        }
        let a_bytes: [u8; WITNESS_LEN] = bytes[..WITNESS_LEN]
            .try_into()
            .map_err(|_| FraudError::InvalidLength(bytes.len()))?;
        let b_bytes: [u8; WITNESS_LEN] = bytes[WITNESS_LEN..]
            .try_into()
            .map_err(|_| FraudError::InvalidLength(bytes.len()))?;
        let a = FrameWitness::decode_unchecked(&a_bytes)?;
        let b = FrameWitness::decode_unchecked(&b_bytes)?;
        let proof = Self { a, b };
        let verified = proof.verify()?;
        if verified.id_a >= verified.id_b {
            return Err(FraudError::NotCanonical);
        }
        Ok(proof)
    }

    /// Verifies both witnesses with strict Ed25519 verification and zero keys.
    pub fn verify(&self) -> Result<VerifiedFraud, FraudError> {
        let (ha, id_a) = self.a.verify()?;
        let (hb, id_b) = self.b.verify()?;
        validate_conflict(&ha, id_a, &hb, id_b)?;
        Ok(VerifiedFraud {
            vault: ha.vault,
            author: ha.author,
            log: ha.kind.log_kind(),
            seq: ha.seq,
            id_a,
            id_b,
        })
    }

    /// Returns the content hash `BLAKE3(encode())` used for `x/<hash>` storage.
    pub fn proof_hash(&self) -> [u8; 32] {
        blake3::hash(&self.encode()).into()
    }

    /// First witness (`id_a < id_b`).
    pub const fn witness_a(&self) -> &FrameWitness {
        &self.a
    }

    /// Second witness (`id_a < id_b`).
    pub const fn witness_b(&self) -> &FrameWitness {
        &self.b
    }
}

fn validate_conflict(
    h1: &FrameHeader,
    id1: FrameId,
    h2: &FrameHeader,
    id2: FrameId,
) -> Result<(), FraudError> {
    if h1.vault != h2.vault {
        return Err(FraudError::DifferentVault);
    }
    if h1.author != h2.author {
        return Err(FraudError::DifferentAuthor);
    }
    if h1.kind.log_kind() != h2.kind.log_kind() {
        return Err(FraudError::DifferentLog);
    }
    if h1.seq != h2.seq {
        return Err(FraudError::DifferentSeq);
    }
    if id1 == id2 {
        return Err(FraudError::SameFrame);
    }
    Ok(())
}

/// Scans a collection of verified frames and returns canonical `FraudProof`s for every
/// equivocation observed at the same `(vault, log_kind, author, seq)`.
pub fn detect_fraud_in_frames<'a>(frames: impl IntoIterator<Item = &'a Frame>) -> Vec<FraudProof> {
    let mut by_slot: BTreeMap<(VaultId, LogKind, DeviceId, u64), BTreeMap<FrameId, &'a Frame>> =
        BTreeMap::new();
    for frame in frames {
        let h = frame.header();
        by_slot
            .entry((h.vault, h.kind.log_kind(), h.author, h.seq))
            .or_default()
            .insert(frame.id(), frame);
    }
    let mut proofs = Vec::new();
    for group in by_slot.into_values() {
        if group.len() < 2 {
            continue;
        }
        let mut iter = group.into_values();
        let Some(first) = iter.next() else {
            continue;
        };
        for other in iter {
            if let Ok(proof) = FraudProof::from_frames(first, other) {
                proofs.push(proof);
            }
        }
    }
    proofs
}
