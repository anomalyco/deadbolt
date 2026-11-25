//! Deadbolt v2 core: cryptography, canonical frames, epochs, recovery-lineage resolver, and fraud proofs.
//!
//! Dark module (PR 7a): pure, deterministic, `unsafe_code = "forbid"`, and `wasm32`-clean.
//! Not yet wired into the v1 engine or CLI.

pub mod builder;
pub mod codec;
pub mod crypto;
pub mod epoch;
pub mod frame;
pub mod fraud;
pub mod membership;

#[cfg(test)]
mod tests;

pub use builder::{
    back_link_aad, build_add_frame, build_create_frame, build_recovery_repair_rewrap,
    build_remove_frame, build_rewrap_frame, build_rotate_recovery_frame,
    build_standalone_rotate_frame, rewrap_wrap_aad, rotate_wrap_aad,
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
    sign, unwrap_epoch_key, verify_strict, wrap_epoch_key, wrap_info,
};
pub use epoch::{
    BadCommit, EpochError, EpochGraph, EpochInfo, EpochKeyring, UnlockReport, WrapOffer,
    WriteEpochDecision,
};
pub use frame::{
    Frame, FrameError, FrameHeader, FrameKind, FrameWitness, HEADER_LEN, LogKind, MAGIC,
    MAX_BACK_LINKS, MAX_BODY_LEN, MAX_DEPS, MAX_PARENTS, MAX_WRAPS, MIN_FRAME_LEN,
    MIN_SEALED_BODY_LEN, SIGNATURE_LEN, WITNESS_LEN, frame_signature_message, join_consent_message,
    rotate_recovery_consent_message, sign_join_consent, sign_rotate_recovery_consent,
};
pub use fraud::{FRAUD_PROOF_LEN, FraudError, FraudProof, VerifiedFraud, detect_fraud_in_frames};
pub use membership::{ParkingReason, ParkingStatus, ResolvedMembership, check_parking, resolve};
