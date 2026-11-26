//! Deadbolt v2 core: cryptography, canonical frames, epochs, recovery-lineage resolver, fraud
//! proofs, delta clocks, the data-plane fold, checkpoints and the GC planner.
//!
//! Pure, deterministic, `unsafe_code = "forbid"`, and `wasm32`-clean.

pub mod builder;
pub mod causal;
pub mod checkpoint;
pub mod clock;
pub mod codec;
pub mod crypto;
mod dag;
pub mod data;
pub mod epoch;
pub mod fold;
pub mod frame;
pub mod fraud;
pub mod gc;
pub mod membership;
pub mod pack;
pub mod state;
pub mod wire;

#[cfg(test)]
mod tests;

pub use builder::{
    back_link_aad, build_add_frame, build_create_frame, build_recovery_repair_rewrap,
    build_remove_frame, build_rewrap_frame, build_rotate_recovery_frame,
    build_standalone_rotate_frame, rewrap_wrap_aad, rotate_wrap_aad,
};
pub use causal::{Closure, SeenBy};
pub use checkpoint::{
    CheckpointError, CheckpointPayload, CheckpointVerdict, PackCommitment, build_checkpoint,
    fold_at_frontier, verify_checkpoint,
};
pub use clock::{
    Causality, DeltaClock, Dot, VectorClock, compare, diff_clock, frame_clock, happened_before,
    tie_break,
};
pub use codec::{
    MemberBody, MemberOp, Rewrap, Rotate, member_body_wire_len, member_op_wire_len,
    rewrap_wire_len, rotate_wire_len, validate_member_body,
};
pub use crypto::{
    BACK_LINK_LEN, CryptoError, DeviceKeys, EpochId, EpochKey, FrameId, KemPublic, KemSecret,
    NONCE_LEN, NetPublic, NetSecret, PADME_FLOOR, RecoverySecret, SUITE_X25519_WRAP,
    SUITE_XWING_RESERVED, TAG_LEN, WRAP_LEN, aead_open, aead_seal, derive_frame_id,
    derive_vault_id, open_back_link, padme_pad, padme_padded_len, padme_unpad, seal_back_link,
    sign, unwrap_epoch_key, verify_recovery_wrap, verify_strict, wrap_epoch_key, wrap_info,
    wrap_recovery_epoch_key,
};
pub use data::{
    DataBody, DataFrame, DataOp, DataPayload, FieldValue, MAX_FIELD_VALUE_LEN, MAX_LABEL_LEN,
    MAX_OPS, honest_clock, next_dclock,
};
pub use epoch::{
    BadCommit, EpochError, EpochGraph, EpochInfo, EpochKeyring, UnlockReport, WrapOffer,
    WriteEpochDecision,
};
pub use fold::{
    FoldContext, adders_from_frames, check_counts, check_still_valid, compact,
    fold_from_checkpoint, fold_from_scratch, resolved_frames, uncounted_own_frames,
};
pub use frame::{
    Frame, FrameError, FrameHeader, FrameKind, FrameWitness, HEADER_LEN, LogKind, MAGIC,
    MAX_BACK_LINKS, MAX_BODY_LEN, MAX_DEPS, MAX_PARENTS, MAX_WRAPS, MIN_FRAME_LEN,
    MIN_SEALED_BODY_LEN, SIGNATURE_LEN, WITNESS_LEN, frame_signature_message, join_consent_message,
    rotate_recovery_consent_message, sign_join_consent, sign_rotate_recovery_consent,
};
pub use fraud::{FRAUD_PROOF_LEN, FraudError, FraudProof, VerifiedFraud, detect_fraud_in_frames};
pub use gc::{
    CHECKPOINT_TRIGGER_BYTES, CHECKPOINT_TRIGGER_FRAMES, Eligibility, GC_GRACE_MS, GcCheckpoint,
    GcFrame, GcPlan, plan_gc, removal_last_seen, should_checkpoint,
};
pub use membership::{ParkingReason, ParkingStatus, ResolvedMembership, check_parking, resolve};
pub use pack::{Pack, PackMeta};
pub use state::{
    ClockBook, DeviceCardValue, DisputeRecord, FoldedState, ItemState, Life, Register, Tombstone,
    Write, state_mac,
};
pub use wire::PayloadError;
