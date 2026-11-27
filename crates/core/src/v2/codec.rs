//! Canonical binary encoding, decoding, and rule E1 structural validation for `MemberBody`.

use crate::id::{DeviceId, Signature};

use super::crypto::{
    BACK_LINK_LEN, EpochId, FrameId, KemPublic, KemSecret, NetPublic, WRAP_LEN, derive_vault_id,
    verify_strict,
};
use super::frame::{
    FrameError, FrameHeader, JoinConsent, MAX_BACK_LINKS, MAX_BODY_LEN, MAX_DEPS, MAX_PARENTS,
    MAX_WRAPS, rotate_recovery_consent_message,
};

/// Encrypted epoch wrap distribution carried by `MemberOp::Rewrap` or `MemberOp::Add`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rewrap {
    pub epoch: EpochId,
    pub suite: u8,
    pub wraps: Vec<(DeviceId, [u8; WRAP_LEN])>,
}

/// Optional atomic epoch rotation attached to a `Member` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotate {
    pub suite: u8,
    pub parents: Vec<EpochId>,
    pub commit: [u8; 32],
    pub back: Vec<(EpochId, [u8; BACK_LINK_LEN])>,
    pub wraps: Vec<(DeviceId, [u8; WRAP_LEN])>,
}

/// Plaintext membership operations (keys and hashes only; zero human labels).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberOp {
    Create {
        nonce: [u8; 32],
        recovery_kem: KemPublic,
    },
    /// `consent` carries the device's transport key, signed by the device
    /// and by that key.
    Add {
        device: DeviceId,
        kem: KemPublic,
        consent: JoinConsent,
        rewrap: Option<Rewrap>,
    },
    Remove {
        device: DeviceId,
        last_seen_seq: Option<u64>,
    },
    RotateRecovery {
        new: DeviceId,
        new_kem: KemPublic,
        consent: Signature,
    },
    Rewrap(Rewrap),
}

/// Decoded plaintext body of a `Member` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberBody {
    /// Causal membership dependencies, strictly sorted and unique.
    pub deps: Vec<FrameId>,
    /// Membership operation, or `None` for a standalone clean-tip/repair `Rotate`.
    pub op: Option<MemberOp>,
    /// Atomic epoch rotation (required on Create/Remove/RotateRecovery/None; forbidden on Add/Rewrap).
    pub rotate: Option<Rotate>,
}

/// Exact wire byte length of a `Rewrap` given its recipient count.
pub const fn rewrap_wire_len(wrap_count: usize) -> usize {
    32 + 1 + 4 + wrap_count * (32 + WRAP_LEN)
}

/// Exact wire byte length of a `Rotate` given its collection counts.
pub const fn rotate_wire_len(parents_len: usize, back_len: usize, wraps_len: usize) -> usize {
    1 + 4
        + parents_len * 32
        + 32
        + 4
        + back_len * (32 + BACK_LINK_LEN)
        + 4
        + wraps_len * (32 + WRAP_LEN)
}

/// Exact wire byte length of a `MemberBody` before sealing wraps/back-links.
pub fn member_body_wire_len(
    deps_len: usize,
    op_wire_len: Option<usize>,
    rotate_shape: Option<(usize, usize, usize)>,
) -> usize {
    let deps = 4 + deps_len * 32;
    let op = op_wire_len.map_or(1, |n| 1 + n);
    let rot = rotate_shape.map_or(1, |(p, b, w)| 1 + rotate_wire_len(p, b, w));
    deps + op + rot
}

/// Wire byte length of a `MemberOp` (including its 1-byte discriminant tag).
pub fn member_op_wire_len(op: &MemberOp) -> usize {
    match op {
        MemberOp::Create { .. } => 1 + 32 + 32,
        MemberOp::Add { rewrap, .. } => {
            1 + 32
                + 32
                + 32
                + 64
                + 64
                + 1
                + rewrap
                    .as_ref()
                    .map_or(0, |r| rewrap_wire_len(r.wraps.len()))
        }
        MemberOp::Remove { last_seen_seq, .. } => {
            1 + 32 + 1 + if last_seen_seq.is_some() { 8 } else { 0 }
        }
        MemberOp::RotateRecovery { .. } => 1 + 32 + 32 + 64,
        MemberOp::Rewrap(r) => 1 + rewrap_wire_len(r.wraps.len()),
    }
}

impl MemberBody {
    /// Encodes a `MemberBody` canonically.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        encode_u32(&mut out, self.deps.len())?;
        for dep in &self.deps {
            out.extend_from_slice(dep.as_bytes());
        }
        match &self.op {
            None => out.push(0),
            Some(op) => {
                out.push(1);
                encode_member_op(&mut out, op)?;
            }
        }
        match &self.rotate {
            None => out.push(0),
            Some(rot) => {
                out.push(1);
                encode_rotate(&mut out, rot)?;
            }
        }
        Ok(out)
    }
}

fn encode_u32(out: &mut Vec<u8>, len: usize) -> Result<(), FrameError> {
    let n = u32::try_from(len).map_err(|_| FrameError::BodyTooLarge {
        len,
        max: MAX_BODY_LEN,
    })?;
    out.extend_from_slice(&n.to_be_bytes());
    Ok(())
}

fn encode_rewrap(out: &mut Vec<u8>, r: &Rewrap) -> Result<(), FrameError> {
    out.extend_from_slice(r.epoch.as_bytes());
    out.push(r.suite);
    encode_u32(out, r.wraps.len())?;
    for (recipient, wrap) in &r.wraps {
        out.extend_from_slice(recipient.as_bytes());
        out.extend_from_slice(wrap);
    }
    Ok(())
}

fn encode_rotate(out: &mut Vec<u8>, rot: &Rotate) -> Result<(), FrameError> {
    out.push(rot.suite);
    encode_u32(out, rot.parents.len())?;
    for parent in &rot.parents {
        out.extend_from_slice(parent.as_bytes());
    }
    out.extend_from_slice(&rot.commit);
    encode_u32(out, rot.back.len())?;
    for (parent, sealed) in &rot.back {
        out.extend_from_slice(parent.as_bytes());
        out.extend_from_slice(sealed);
    }
    encode_u32(out, rot.wraps.len())?;
    for (recipient, wrap) in &rot.wraps {
        out.extend_from_slice(recipient.as_bytes());
        out.extend_from_slice(wrap);
    }
    Ok(())
}

fn encode_member_op(out: &mut Vec<u8>, op: &MemberOp) -> Result<(), FrameError> {
    match op {
        MemberOp::Create {
            nonce,
            recovery_kem,
        } => {
            out.push(0);
            out.extend_from_slice(nonce);
            out.extend_from_slice(recovery_kem.as_bytes());
        }
        MemberOp::Add {
            device,
            kem,
            consent,
            rewrap,
        } => {
            out.push(1);
            out.extend_from_slice(device.as_bytes());
            out.extend_from_slice(kem.as_bytes());
            out.extend_from_slice(consent.net.as_bytes());
            out.extend_from_slice(consent.consent.as_bytes());
            out.extend_from_slice(consent.net_proof.as_bytes());
            match rewrap {
                None => out.push(0),
                Some(r) => {
                    out.push(1);
                    encode_rewrap(out, r)?;
                }
            }
        }
        MemberOp::Remove {
            device,
            last_seen_seq,
        } => {
            out.push(2);
            out.extend_from_slice(device.as_bytes());
            match last_seen_seq {
                None => out.push(0),
                Some(seq) => {
                    out.push(1);
                    out.extend_from_slice(&seq.to_be_bytes());
                }
            }
        }
        MemberOp::RotateRecovery {
            new,
            new_kem,
            consent,
        } => {
            out.push(3);
            out.extend_from_slice(new.as_bytes());
            out.extend_from_slice(new_kem.as_bytes());
            out.extend_from_slice(consent.as_bytes());
        }
        MemberOp::Rewrap(r) => {
            out.push(4);
            encode_rewrap(out, r)?;
        }
    }
    Ok(())
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], FrameError> {
        if self.0.len() < n {
            return Err(FrameError::UnexpectedEnd);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FrameError> {
        self.take(N)?
            .try_into()
            .map_err(|_| FrameError::UnexpectedEnd)
    }

    fn u8(&mut self) -> Result<u8, FrameError> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32, FrameError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, FrameError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    fn count(&mut self, max: usize, item_size: usize) -> Result<usize, FrameError> {
        let count = self.u32()? as usize;
        if count > max {
            return Err(FrameError::CollectionTooLarge { count, max });
        }
        let min_bytes = count
            .checked_mul(item_size)
            .ok_or(FrameError::UnexpectedEnd)?;
        if self.0.len() < min_bytes {
            return Err(FrameError::UnexpectedEnd);
        }
        Ok(count)
    }

    fn finish(self) -> Result<(), FrameError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(FrameError::TrailingBytes)
        }
    }
}

fn decode_rewrap(r: &mut Reader<'_>) -> Result<Rewrap, FrameError> {
    let epoch = EpochId::from_bytes(r.array::<32>()?);
    let suite = r.u8()?;
    let wraps_len = r.count(MAX_WRAPS, 32 + WRAP_LEN)?;
    let mut wraps = Vec::with_capacity(wraps_len);
    let mut prev: Option<DeviceId> = None;
    for _ in 0..wraps_len {
        let recipient = DeviceId::from_bytes(r.array::<32>()?);
        if let Some(p) = prev
            && recipient <= p
        {
            return Err(FrameError::NotCanonical("rewrap wraps"));
        }
        prev = Some(recipient);
        wraps.push((recipient, r.array::<WRAP_LEN>()?));
    }
    Ok(Rewrap {
        epoch,
        suite,
        wraps,
    })
}

fn decode_rotate(r: &mut Reader<'_>) -> Result<Rotate, FrameError> {
    let suite = r.u8()?;
    let parents_len = r.count(MAX_PARENTS, 32)?;
    let mut parents = Vec::with_capacity(parents_len);
    let mut prev_parent: Option<EpochId> = None;
    for _ in 0..parents_len {
        let p = EpochId::from_bytes(r.array::<32>()?);
        if let Some(prev) = prev_parent
            && p <= prev
        {
            return Err(FrameError::NotCanonical("rotate parents"));
        }
        prev_parent = Some(p);
        parents.push(p);
    }
    let commit = r.array::<32>()?;
    let back_len = r.count(MAX_BACK_LINKS, 32 + BACK_LINK_LEN)?;
    let mut back = Vec::with_capacity(back_len);
    let mut prev_back: Option<EpochId> = None;
    for _ in 0..back_len {
        let parent = EpochId::from_bytes(r.array::<32>()?);
        if let Some(prev) = prev_back
            && parent <= prev
        {
            return Err(FrameError::NotCanonical("rotate back"));
        }
        prev_back = Some(parent);
        back.push((parent, r.array::<BACK_LINK_LEN>()?));
    }
    let wraps_len = r.count(MAX_WRAPS, 32 + WRAP_LEN)?;
    let mut wraps = Vec::with_capacity(wraps_len);
    let mut prev_wrap: Option<DeviceId> = None;
    for _ in 0..wraps_len {
        let recipient = DeviceId::from_bytes(r.array::<32>()?);
        if let Some(prev) = prev_wrap
            && recipient <= prev
        {
            return Err(FrameError::NotCanonical("rotate wraps"));
        }
        prev_wrap = Some(recipient);
        wraps.push((recipient, r.array::<WRAP_LEN>()?));
    }
    Ok(Rotate {
        suite,
        parents,
        commit,
        back,
        wraps,
    })
}

fn decode_member_op(r: &mut Reader<'_>) -> Result<MemberOp, FrameError> {
    match r.u8()? {
        0 => Ok(MemberOp::Create {
            nonce: r.array::<32>()?,
            recovery_kem: KemPublic::from_bytes(r.array::<32>()?),
        }),
        1 => {
            let device = DeviceId::from_bytes(r.array::<32>()?);
            let kem = KemPublic::from_bytes(r.array::<32>()?);
            let consent = JoinConsent {
                net: NetPublic::from_bytes(r.array::<32>()?),
                consent: Signature::from_bytes(r.array::<64>()?),
                net_proof: Signature::from_bytes(r.array::<64>()?),
            };
            let rewrap = match r.u8()? {
                0 => None,
                1 => Some(decode_rewrap(r)?),
                other => return Err(FrameError::InvalidOptionTag(other)),
            };
            Ok(MemberOp::Add {
                device,
                kem,
                consent,
                rewrap,
            })
        }
        2 => {
            let device = DeviceId::from_bytes(r.array::<32>()?);
            let last_seen_seq = match r.u8()? {
                0 => None,
                1 => Some(r.u64()?),
                other => return Err(FrameError::InvalidOptionTag(other)),
            };
            Ok(MemberOp::Remove {
                device,
                last_seen_seq,
            })
        }
        3 => Ok(MemberOp::RotateRecovery {
            new: DeviceId::from_bytes(r.array::<32>()?),
            new_kem: KemPublic::from_bytes(r.array::<32>()?),
            consent: Signature::from_bytes(r.array::<64>()?),
        }),
        4 => Ok(MemberOp::Rewrap(decode_rewrap(r)?)),
        other => Err(FrameError::InvalidMemberOpTag(other)),
    }
}

pub(crate) fn decode_member_body(
    header: &FrameHeader,
    bytes: &[u8],
) -> Result<MemberBody, FrameError> {
    let mut r = Reader(bytes);
    let deps_len = r.count(MAX_DEPS, 32)?;
    let mut deps = Vec::with_capacity(deps_len);
    let mut prev_dep: Option<FrameId> = None;
    for _ in 0..deps_len {
        let dep = FrameId::from_bytes(r.array::<32>()?);
        if let Some(prev) = prev_dep
            && dep <= prev
        {
            return Err(FrameError::NotCanonical("deps"));
        }
        prev_dep = Some(dep);
        deps.push(dep);
    }
    let op = match r.u8()? {
        0 => None,
        1 => Some(decode_member_op(&mut r)?),
        other => return Err(FrameError::InvalidOptionTag(other)),
    };
    let rotate = match r.u8()? {
        0 => None,
        1 => Some(decode_rotate(&mut r)?),
        other => return Err(FrameError::InvalidOptionTag(other)),
    };
    r.finish()?;
    let body = MemberBody { deps, op, rotate };
    validate_member_body(header, &body)?;
    Ok(body)
}

fn validate_sorted_unique<T: Ord>(items: &[T], name: &'static str) -> Result<(), FrameError> {
    for pair in items.windows(2) {
        if pair[1] <= pair[0] {
            return Err(FrameError::NotCanonical(name));
        }
    }
    Ok(())
}

fn validate_rewrap(r: &Rewrap) -> Result<(), FrameError> {
    if r.epoch.is_zero() {
        return Err(FrameError::InvalidStructure(
            "rewrap epoch must be non-zero",
        ));
    }
    if r.suite == 0 {
        return Err(FrameError::InvalidStructure(
            "rewrap suite must be non-zero",
        ));
    }
    if r.wraps.is_empty() {
        return Err(FrameError::InvalidStructure(
            "rewrap must contain at least one wrap",
        ));
    }
    if r.wraps.len() > MAX_WRAPS {
        return Err(FrameError::CollectionTooLarge {
            count: r.wraps.len(),
            max: MAX_WRAPS,
        });
    }
    for pair in r.wraps.windows(2) {
        if pair[1].0 <= pair[0].0 {
            return Err(FrameError::NotCanonical("rewrap wraps"));
        }
    }
    Ok(())
}

fn validate_rotate(rot: &Rotate) -> Result<(), FrameError> {
    if rot.suite == 0 {
        return Err(FrameError::InvalidStructure(
            "rotate suite must be non-zero",
        ));
    }
    if rot.parents.len() > MAX_PARENTS {
        return Err(FrameError::CollectionTooLarge {
            count: rot.parents.len(),
            max: MAX_PARENTS,
        });
    }
    validate_sorted_unique(&rot.parents, "rotate parents")?;
    if rot.back.len() > MAX_BACK_LINKS {
        return Err(FrameError::CollectionTooLarge {
            count: rot.back.len(),
            max: MAX_BACK_LINKS,
        });
    }
    for pair in rot.back.windows(2) {
        if pair[1].0 <= pair[0].0 {
            return Err(FrameError::NotCanonical("rotate back"));
        }
    }
    for (parent, _) in &rot.back {
        if rot.parents.binary_search(parent).is_err() {
            return Err(FrameError::InvalidStructure(
                "back-link epoch must appear in rotate parents",
            ));
        }
    }
    if rot.wraps.is_empty() {
        return Err(FrameError::InvalidStructure(
            "rotate must contain at least one wrap",
        ));
    }
    if rot.wraps.len() > MAX_WRAPS {
        return Err(FrameError::CollectionTooLarge {
            count: rot.wraps.len(),
            max: MAX_WRAPS,
        });
    }
    for pair in rot.wraps.windows(2) {
        if pair[1].0 <= pair[0].0 {
            return Err(FrameError::NotCanonical("rotate wraps"));
        }
    }
    Ok(())
}

/// Validates canonicality, E1 atomicity, and consent signatures of a `MemberBody`.
pub fn validate_member_body(header: &FrameHeader, body: &MemberBody) -> Result<(), FrameError> {
    if body.deps.len() > MAX_DEPS {
        return Err(FrameError::CollectionTooLarge {
            count: body.deps.len(),
            max: MAX_DEPS,
        });
    }
    validate_sorted_unique(&body.deps, "deps")?;
    if header.seq > 0 && body.deps.binary_search(&header.prev).is_err() {
        return Err(FrameError::InvalidStructure(
            "member frame with seq > 0 must include prev in deps",
        ));
    }
    if let Some(rot) = &body.rotate {
        validate_rotate(rot)?;
    }
    let kem = match &body.op {
        Some(MemberOp::Create { recovery_kem, .. }) => Some(recovery_kem),
        Some(MemberOp::Add { kem, .. }) => Some(kem),
        Some(MemberOp::RotateRecovery { new_kem, .. }) => Some(new_kem),
        _ => None,
    };
    // Every clamped X25519 scalar rejects the same non-contributory public keys.
    if kem.is_some_and(|kem| KemSecret::from_bytes(&[0; 32]).diffie_hellman(kem).is_err()) {
        return Err(FrameError::InvalidStructure(
            "non-contributory membership KEM key",
        ));
    }
    match (&body.op, &body.rotate) {
        (Some(MemberOp::Create { nonce, .. }), Some(rot)) => {
            if header.seq != 0 || !body.deps.is_empty() {
                return Err(FrameError::InvalidStructure(
                    "create must have seq 0 and no deps",
                ));
            }
            if derive_vault_id(&header.author, nonce) != header.vault {
                return Err(FrameError::InvalidStructure(
                    "create vault id does not match author and nonce",
                ));
            }
            if !rot.parents.is_empty() || !rot.back.is_empty() {
                return Err(FrameError::InvalidStructure(
                    "create rotate must have no parents or back-links",
                ));
            }
        }
        (Some(MemberOp::Create { .. }), None) => {
            return Err(FrameError::InvalidStructure(
                "create requires atomic rotate",
            ));
        }
        (Some(MemberOp::Remove { .. }), Some(_)) => {}
        (Some(MemberOp::Remove { .. }), None) => {
            return Err(FrameError::InvalidStructure(
                "remove requires atomic rotate",
            ));
        }
        (
            Some(MemberOp::RotateRecovery {
                new,
                new_kem,
                consent,
            }),
            Some(_),
        ) => {
            if *new == header.author {
                return Err(FrameError::InvalidStructure(
                    "rotate recovery target must differ from old root",
                ));
            }
            let msg = rotate_recovery_consent_message(&header.vault, &header.author, new, new_kem);
            if !verify_strict(new, &msg, consent) {
                return Err(FrameError::InvalidConsent);
            }
        }
        (Some(MemberOp::RotateRecovery { .. }), None) => {
            return Err(FrameError::InvalidStructure(
                "rotate recovery requires atomic rotate",
            ));
        }
        (
            Some(MemberOp::Add {
                device,
                kem,
                consent,
                rewrap,
            }),
            None,
        ) => {
            if !consent.verify(&header.vault, &header.author, device, kem) {
                return Err(FrameError::InvalidConsent);
            }
            if let Some(r) = rewrap {
                validate_rewrap(r)?;
            }
        }
        (Some(MemberOp::Add { .. }), Some(_)) => {
            return Err(FrameError::InvalidStructure("add must never carry rotate"));
        }
        (Some(MemberOp::Rewrap(r)), None) => validate_rewrap(r)?,
        (Some(MemberOp::Rewrap(_)), Some(_)) => {
            return Err(FrameError::InvalidStructure("rewrap must not carry rotate"));
        }
        (None, Some(_)) => {}
        (None, None) => {
            return Err(FrameError::InvalidStructure(
                "member frame must carry an op or a rotate",
            ));
        }
    }
    Ok(())
}
