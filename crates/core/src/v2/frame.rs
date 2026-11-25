//! Canonical Deadbolt v2 `Frame` wire format, fixed 145-byte headers, witnesses, and sealing.
//!
//! Fixed 145-byte header:
//! `"DBF2" || kind:u8 || vault:32 || author:32 || seq:u64_be || prev:32 || epoch:32 || blen:u32_be`.
//! Wire layout: `hdr[145] || body[blen] || sig[64]`.

use zeroize::Zeroizing;

use crate::id::{DeviceId, DeviceSecret, Signature, VaultId};

use super::codec::decode_member_body;
pub use super::codec::{
    MemberBody, MemberOp, Rewrap, Rotate, member_body_wire_len, member_op_wire_len,
    rewrap_wire_len, rotate_wire_len, validate_member_body,
};
use super::crypto::{
    CryptoError, EpochId, EpochKey, FrameId, KemPublic, NONCE_LEN, PADME_FLOOR, TAG_LEN, aead_open,
    aead_seal, derive_frame_id, padme_pad, padme_padded_len, padme_unpad, sign, verify_strict,
};

/// Wire magic prefix for v2 frames.
pub const MAGIC: [u8; 4] = *b"DBF2";
/// Fixed v2 frame header byte length.
pub const HEADER_LEN: usize = 145;
/// Ed25519 signature byte length.
pub const SIGNATURE_LEN: usize = 64;
/// Minimum wire frame length (`HEADER_LEN + SIGNATURE_LEN`).
pub const MIN_FRAME_LEN: usize = HEADER_LEN + SIGNATURE_LEN;
/// Byte length of one `FrameWitness` (`hdr[145] || body_hash[32] || sig[64]`).
pub const WITNESS_LEN: usize = HEADER_LEN + 32 + SIGNATURE_LEN;
/// Maximum allowed body length (16 MiB), checked before allocation.
pub const MAX_BODY_LEN: usize = 16 * 1024 * 1024;
/// Minimum encrypted body length for `Data` / `Checkpoint` frames.
pub const MIN_SEALED_BODY_LEN: usize = NONCE_LEN + PADME_FLOOR + TAG_LEN;

/// Maximum causal dependencies per `Member` frame (checked before allocation).
pub const MAX_DEPS: usize = 4096;
/// Maximum parent epochs listed in a `Rotate` (checked before allocation).
pub const MAX_PARENTS: usize = 256;
/// Maximum encrypted back-links in a `Rotate` (checked before allocation).
pub const MAX_BACK_LINKS: usize = 256;
/// Maximum recipient wraps in a `Rotate` or `Rewrap` (checked before allocation).
pub const MAX_WRAPS: usize = 256;

const SIG_FRAME_PREFIX: &[u8] = b"deadbolt/v2 frame\0";
const SIG_JOIN_CONSENT_PREFIX: &[u8] = b"deadbolt/v2 join consent\0";
const SIG_ROTATE_RECOVERY_CONSENT_PREFIX: &[u8] = b"deadbolt/v2 rotate recovery consent\0";

/// Frame decoding, structural validation, and sealing errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("invalid frame magic")]
    BadMagic,
    #[error("invalid frame kind {0}")]
    InvalidKind(u8),
    #[error("unexpected end of frame")]
    UnexpectedEnd,
    #[error("trailing bytes after frame body")]
    TrailingBytes,
    #[error("frame body length {len} exceeds limit {max}")]
    BodyTooLarge { len: usize, max: usize },
    #[error("collection count {count} exceeds limit {max}")]
    CollectionTooLarge { count: usize, max: usize },
    #[error("invalid header invariants: {0}")]
    InvalidHeader(&'static str),
    #[error("frame signature failed strict verification")]
    BadSignature,
    #[error("invalid member op tag {0}")]
    InvalidMemberOpTag(u8),
    #[error("invalid option tag {0}")]
    InvalidOptionTag(u8),
    #[error("non-canonical ordering or duplicate entry in {0}")]
    NotCanonical(&'static str),
    #[error("invalid member body structure: {0}")]
    InvalidStructure(&'static str),
    #[error("invalid consent signature")]
    InvalidConsent,
    #[error("frame kind does not carry sealed payload")]
    NotSealedFrame,
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

/// Which per-author append-only log a frame belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogKind {
    /// Membership log (`m/<author>/<seq>`).
    Member,
    /// Data and Checkpoint log (`d/<author>/<seq>`).
    Data,
}

/// Wire frame kind discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum FrameKind {
    Member = 0,
    Data = 1,
    Checkpoint = 2,
}

impl FrameKind {
    /// Parses a wire kind byte.
    pub fn from_u8(tag: u8) -> Result<Self, FrameError> {
        match tag {
            0 => Ok(Self::Member),
            1 => Ok(Self::Data),
            2 => Ok(Self::Checkpoint),
            other => Err(FrameError::InvalidKind(other)),
        }
    }

    /// Returns the log stream (`Member` or `Data`) that sequences this frame kind.
    pub const fn log_kind(self) -> LogKind {
        match self {
            Self::Member => LogKind::Member,
            Self::Data | Self::Checkpoint => LogKind::Data,
        }
    }
}

/// Fixed 145-byte canonical v2 frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub kind: FrameKind,
    pub vault: VaultId,
    pub author: DeviceId,
    pub seq: u64,
    pub prev: FrameId,
    pub epoch: EpochId,
    pub body_len: u32,
}

impl FrameHeader {
    /// Encodes the header into its exact 145-byte canonical representation.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4] = self.kind as u8;
        out[5..37].copy_from_slice(self.vault.as_bytes());
        out[37..69].copy_from_slice(self.author.as_bytes());
        out[69..77].copy_from_slice(&self.seq.to_be_bytes());
        out[77..109].copy_from_slice(self.prev.as_bytes());
        out[109..141].copy_from_slice(self.epoch.as_bytes());
        out[141..145].copy_from_slice(&self.body_len.to_be_bytes());
        out
    }

    /// Decodes and validates a 145-byte header.
    pub fn decode(bytes: &[u8; HEADER_LEN]) -> Result<Self, FrameError> {
        if bytes[0..4] != MAGIC {
            return Err(FrameError::BadMagic);
        }
        let hdr = Self {
            kind: FrameKind::from_u8(bytes[4])?,
            vault: VaultId::from_bytes(copy_32(&bytes[5..37])?),
            author: DeviceId::from_bytes(copy_32(&bytes[37..69])?),
            seq: u64::from_be_bytes(copy_8(&bytes[69..77])?),
            prev: FrameId::from_bytes(copy_32(&bytes[77..109])?),
            epoch: EpochId::from_bytes(copy_32(&bytes[109..141])?),
            body_len: u32::from_be_bytes(copy_4(&bytes[141..145])?),
        };
        hdr.validate()?;
        Ok(hdr)
    }

    /// Validates header-level structural invariants.
    pub fn validate(&self) -> Result<(), FrameError> {
        if self.seq == 0 && !self.prev.is_zero() {
            return Err(FrameError::InvalidHeader("seq 0 must have zero prev"));
        }
        if self.seq > 0 && self.prev.is_zero() {
            return Err(FrameError::InvalidHeader("seq > 0 must have non-zero prev"));
        }
        match self.kind {
            FrameKind::Member if !self.epoch.is_zero() => {
                return Err(FrameError::InvalidHeader(
                    "member frame must have zero epoch",
                ));
            }
            FrameKind::Data | FrameKind::Checkpoint if self.epoch.is_zero() => {
                return Err(FrameError::InvalidHeader(
                    "data/checkpoint frame must have non-zero epoch",
                ));
            }
            _ => {}
        }
        let len = self.body_len as usize;
        if len > MAX_BODY_LEN {
            return Err(FrameError::BodyTooLarge {
                len,
                max: MAX_BODY_LEN,
            });
        }
        Ok(())
    }
}

/// Keyless 241-byte signed witness of a frame (`hdr[145] || BLAKE3(body)[32] || sig[64]`).
/// Two conflicting witnesses form a 482-byte keyless `FraudProof`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameWitness {
    pub header_bytes: [u8; HEADER_LEN],
    pub body_hash: [u8; 32],
    pub signature: Signature,
}

impl FrameWitness {
    /// Encodes into exactly 241 bytes.
    pub fn encode(&self) -> [u8; WITNESS_LEN] {
        let mut out = [0u8; WITNESS_LEN];
        out[..HEADER_LEN].copy_from_slice(&self.header_bytes);
        out[HEADER_LEN..HEADER_LEN + 32].copy_from_slice(&self.body_hash);
        out[HEADER_LEN + 32..].copy_from_slice(self.signature.as_bytes());
        out
    }

    /// Decodes from 241 bytes without verifying the signature.
    pub fn decode_unchecked(bytes: &[u8; WITNESS_LEN]) -> Result<Self, FrameError> {
        let mut header_bytes = [0u8; HEADER_LEN];
        header_bytes.copy_from_slice(&bytes[..HEADER_LEN]);
        Ok(Self {
            header_bytes,
            body_hash: copy_32(&bytes[HEADER_LEN..HEADER_LEN + 32])?,
            signature: Signature::from_bytes(copy_64(&bytes[HEADER_LEN + 32..])?),
        })
    }

    /// Validates the header, verifies the Ed25519 signature strictly, and returns `(header, FrameId)`.
    pub fn verify(&self) -> Result<(FrameHeader, FrameId), FrameError> {
        let header = FrameHeader::decode(&self.header_bytes)?;
        let msg = frame_signature_message(&self.header_bytes, &self.body_hash);
        if !verify_strict(&header.author, &msg, &self.signature) {
            return Err(FrameError::BadSignature);
        }
        Ok((header, derive_frame_id(&self.header_bytes, &self.body_hash)))
    }
}

/// A verified, decoded Deadbolt v2 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    id: FrameId,
    header: FrameHeader,
    header_bytes: [u8; HEADER_LEN],
    body_hash: [u8; 32],
    body: Vec<u8>,
    member_body: Option<MemberBody>,
    signature: Signature,
}

impl Frame {
    pub const fn id(&self) -> FrameId {
        self.id
    }
    pub const fn header(&self) -> &FrameHeader {
        &self.header
    }
    pub const fn header_bytes(&self) -> &[u8; HEADER_LEN] {
        &self.header_bytes
    }
    pub const fn body_hash(&self) -> &[u8; 32] {
        &self.body_hash
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn member_body(&self) -> Option<&MemberBody> {
        self.member_body.as_ref()
    }
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Extracts the 241-byte keyless `FrameWitness` for fraud-proof construction.
    pub const fn witness(&self) -> FrameWitness {
        FrameWitness {
            header_bytes: self.header_bytes,
            body_hash: self.body_hash,
            signature: self.signature,
        }
    }

    /// Encodes the full wire frame: `hdr[145] || body || sig[64]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.body.len() + SIGNATURE_LEN);
        out.extend_from_slice(&self.header_bytes);
        out.extend_from_slice(&self.body);
        out.extend_from_slice(self.signature.as_bytes());
        out
    }

    /// Decodes a wire frame, verifying header, exact length, strict Ed25519 signature, and body.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < MIN_FRAME_LEN {
            return Err(FrameError::UnexpectedEnd);
        }
        let mut header_bytes = [0u8; HEADER_LEN];
        header_bytes.copy_from_slice(&bytes[..HEADER_LEN]);
        let header = FrameHeader::decode(&header_bytes)?;
        let expected_len = HEADER_LEN
            .checked_add(header.body_len as usize)
            .and_then(|n| n.checked_add(SIGNATURE_LEN))
            .ok_or(FrameError::UnexpectedEnd)?;
        if bytes.len() < expected_len {
            return Err(FrameError::UnexpectedEnd);
        }
        if bytes.len() > expected_len {
            return Err(FrameError::TrailingBytes);
        }
        let body_slice = &bytes[HEADER_LEN..HEADER_LEN + header.body_len as usize];
        let signature =
            Signature::from_bytes(copy_64(&bytes[HEADER_LEN + header.body_len as usize..])?);
        let body_hash: [u8; 32] = blake3::hash(body_slice).into();
        if !verify_strict(
            &header.author,
            &frame_signature_message(&header_bytes, &body_hash),
            &signature,
        ) {
            return Err(FrameError::BadSignature);
        }
        let member_body = match header.kind {
            FrameKind::Member => Some(decode_member_body(&header, body_slice)?),
            FrameKind::Data | FrameKind::Checkpoint => {
                if body_slice.len() < MIN_SEALED_BODY_LEN {
                    return Err(FrameError::UnexpectedEnd);
                }
                None
            }
        };
        let id = derive_frame_id(&header_bytes, &body_hash);
        Ok(Self {
            id,
            header,
            header_bytes,
            body_hash,
            body: body_slice.to_vec(),
            member_body,
            signature,
        })
    }

    /// Builds and signs a canonical `Member` frame from a validated `MemberBody`.
    pub fn sign_member(
        author_secret: &DeviceSecret,
        vault: VaultId,
        seq: u64,
        prev: FrameId,
        member_body: MemberBody,
    ) -> Result<Self, FrameError> {
        let body = member_body.encode()?;
        let body_len = u32::try_from(body.len()).map_err(|_| FrameError::BodyTooLarge {
            len: body.len(),
            max: MAX_BODY_LEN,
        })?;
        let header = FrameHeader {
            kind: FrameKind::Member,
            vault,
            author: author_secret.device_id(),
            seq,
            prev,
            epoch: EpochId::ZERO,
            body_len,
        };
        header.validate()?;
        validate_member_body(&header, &member_body)?;
        let header_bytes = header.encode();
        let body_hash: [u8; 32] = blake3::hash(&body).into();
        let signature = sign(
            author_secret,
            &frame_signature_message(&header_bytes, &body_hash),
        );
        let id = derive_frame_id(&header_bytes, &body_hash);
        Ok(Self {
            id,
            header,
            header_bytes,
            body_hash,
            body,
            member_body: Some(member_body),
            signature,
        })
    }

    /// Seals and signs a `Data` frame under `K_data(epoch)` with Padmé padding and `aad = hdr`.
    pub fn seal_data(
        author_secret: &DeviceSecret,
        vault: VaultId,
        seq: u64,
        prev: FrameId,
        epoch: EpochId,
        epoch_key: &EpochKey,
        plaintext: &[u8],
    ) -> Result<Self, FrameError> {
        Self::seal_kind(
            FrameKind::Data,
            author_secret,
            vault,
            seq,
            prev,
            epoch,
            epoch_key,
            plaintext,
        )
    }

    /// Seals and signs a `Checkpoint` frame shell under `K_data(epoch)` with Padmé padding and `aad = hdr`.
    pub fn seal_checkpoint(
        author_secret: &DeviceSecret,
        vault: VaultId,
        seq: u64,
        prev: FrameId,
        epoch: EpochId,
        epoch_key: &EpochKey,
        plaintext: &[u8],
    ) -> Result<Self, FrameError> {
        Self::seal_kind(
            FrameKind::Checkpoint,
            author_secret,
            vault,
            seq,
            prev,
            epoch,
            epoch_key,
            plaintext,
        )
    }

    #[expect(clippy::too_many_arguments)]
    fn seal_kind(
        kind: FrameKind,
        author_secret: &DeviceSecret,
        vault: VaultId,
        seq: u64,
        prev: FrameId,
        epoch: EpochId,
        epoch_key: &EpochKey,
        plaintext: &[u8],
    ) -> Result<Self, FrameError> {
        let padded_len = padme_padded_len(plaintext.len())?;
        let total_body_len = NONCE_LEN
            .checked_add(padded_len)
            .and_then(|n| n.checked_add(TAG_LEN))
            .ok_or(FrameError::BodyTooLarge {
                len: usize::MAX,
                max: MAX_BODY_LEN,
            })?;
        if total_body_len > MAX_BODY_LEN {
            return Err(FrameError::BodyTooLarge {
                len: total_body_len,
                max: MAX_BODY_LEN,
            });
        }
        let body_len = u32::try_from(total_body_len).map_err(|_| FrameError::BodyTooLarge {
            len: total_body_len,
            max: MAX_BODY_LEN,
        })?;
        let header = FrameHeader {
            kind,
            vault,
            author: author_secret.device_id(),
            seq,
            prev,
            epoch,
            body_len,
        };
        header.validate()?;
        let header_bytes = header.encode();
        let padded = padme_pad(plaintext)?;
        let k_data = epoch_key.data_key(&vault, &epoch);
        let (nonce, ct) = aead_seal(&k_data, &header_bytes, &padded)?;
        let mut body = Vec::with_capacity(total_body_len);
        body.extend_from_slice(&nonce);
        body.extend_from_slice(&ct);
        let body_hash: [u8; 32] = blake3::hash(&body).into();
        let signature = sign(
            author_secret,
            &frame_signature_message(&header_bytes, &body_hash),
        );
        let id = derive_frame_id(&header_bytes, &body_hash);
        Ok(Self {
            id,
            header,
            header_bytes,
            body_hash,
            body,
            member_body: None,
            signature,
        })
    }

    /// Decrypts and unpads a `Data` or `Checkpoint` frame using `epoch_key`.
    pub fn open_sealed(&self, epoch_key: &EpochKey) -> Result<Zeroizing<Vec<u8>>, FrameError> {
        if self.header.kind == FrameKind::Member {
            return Err(FrameError::NotSealedFrame);
        }
        if self.body.len() < MIN_SEALED_BODY_LEN {
            return Err(FrameError::UnexpectedEnd);
        }
        let nonce: [u8; NONCE_LEN] = self.body[..NONCE_LEN]
            .try_into()
            .map_err(|_| FrameError::UnexpectedEnd)?;
        let k_data = epoch_key.data_key(&self.header.vault, &self.header.epoch);
        let padded = aead_open(&k_data, &nonce, &self.header_bytes, &self.body[NONCE_LEN..])?;
        let pt = padme_unpad(&padded)?;
        Ok(Zeroizing::new(pt.to_vec()))
    }
}

/// Computes the exact 195-byte frame signature message:
/// `"deadbolt/v2 frame\0" || hdr[145] || body_hash[32]`.
pub fn frame_signature_message(header_bytes: &[u8; HEADER_LEN], body_hash: &[u8; 32]) -> [u8; 195] {
    let mut msg = [0u8; 195];
    msg[..18].copy_from_slice(SIG_FRAME_PREFIX);
    msg[18..163].copy_from_slice(header_bytes);
    msg[163..195].copy_from_slice(body_hash);
    msg
}

/// Builds the join consent message binding vault, inviter, new device, and its X25519 `kem`.
pub fn join_consent_message(
    vault: &VaultId,
    inviter: &DeviceId,
    device: &DeviceId,
    kem: &KemPublic,
) -> [u8; 153] {
    let mut msg = [0u8; 153];
    msg[..25].copy_from_slice(SIG_JOIN_CONSENT_PREFIX);
    msg[25..57].copy_from_slice(vault.as_bytes());
    msg[57..89].copy_from_slice(inviter.as_bytes());
    msg[89..121].copy_from_slice(device.as_bytes());
    msg[121..153].copy_from_slice(kem.as_bytes());
    msg
}

/// Signs join consent with the joining device's `D_sign`.
pub fn sign_join_consent(
    device_secret: &DeviceSecret,
    vault: &VaultId,
    inviter: &DeviceId,
    kem: &KemPublic,
) -> Signature {
    let msg = join_consent_message(vault, inviter, &device_secret.device_id(), kem);
    sign(device_secret, &msg)
}

/// Builds the `RotateRecovery` consent message signed by the new root's `R_sign`.
pub fn rotate_recovery_consent_message(
    vault: &VaultId,
    old_root: &DeviceId,
    new_root: &DeviceId,
    new_kem: &KemPublic,
) -> [u8; 164] {
    let mut msg = [0u8; 164];
    msg[..36].copy_from_slice(SIG_ROTATE_RECOVERY_CONSENT_PREFIX);
    msg[36..68].copy_from_slice(vault.as_bytes());
    msg[68..100].copy_from_slice(old_root.as_bytes());
    msg[100..132].copy_from_slice(new_root.as_bytes());
    msg[132..164].copy_from_slice(new_kem.as_bytes());
    msg
}

/// Signs `RotateRecovery` consent with the new recovery root's `R_sign`.
pub fn sign_rotate_recovery_consent(
    new_root_secret: &DeviceSecret,
    vault: &VaultId,
    old_root: &DeviceId,
    new_kem: &KemPublic,
) -> Signature {
    let msg =
        rotate_recovery_consent_message(vault, old_root, &new_root_secret.device_id(), new_kem);
    sign(new_root_secret, &msg)
}

fn copy_4(s: &[u8]) -> Result<[u8; 4], FrameError> {
    s.try_into().map_err(|_| FrameError::UnexpectedEnd)
}
fn copy_8(s: &[u8]) -> Result<[u8; 8], FrameError> {
    s.try_into().map_err(|_| FrameError::UnexpectedEnd)
}
fn copy_32(s: &[u8]) -> Result<[u8; 32], FrameError> {
    s.try_into().map_err(|_| FrameError::UnexpectedEnd)
}
fn copy_64(s: &[u8]) -> Result<[u8; 64], FrameError> {
    s.try_into().map_err(|_| FrameError::UnexpectedEnd)
}
