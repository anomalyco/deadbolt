//! Canonical `Member` frame builders and AAD constructors for `deadbolt_core::v2` epochs.

use std::collections::BTreeMap;

use crate::id::{DeviceId, DeviceSecret, Signature, VaultId};

use super::crypto::{
    EpochId, EpochKey, FrameId, KemPublic, RecoverySecret, SUITE_X25519_WRAP, derive_vault_id,
    seal_back_link, wrap_epoch_key, wrap_info,
};
use super::epoch::{EpochError, EpochGraph, EpochKeyring};
use super::frame::{
    Frame, FrameError, FrameHeader, FrameKind, HEADER_LEN, MAX_BODY_LEN, MemberBody, MemberOp,
    Rewrap, Rotate, member_body_wire_len, member_op_wire_len, rewrap_wire_len,
};

/// Builds the 145-byte AAD for `Rotate` wraps.
pub const fn rotate_wrap_aad(header_bytes: &[u8; HEADER_LEN]) -> [u8; HEADER_LEN] {
    *header_bytes
}

/// Builds the 177-byte AAD for `Rewrap` wraps: `hdr[145] || target_epoch[32]`.
pub fn rewrap_wrap_aad(header_bytes: &[u8; HEADER_LEN], target_epoch: &EpochId) -> [u8; 177] {
    let mut out = [0u8; 177];
    out[..HEADER_LEN].copy_from_slice(header_bytes);
    out[HEADER_LEN..].copy_from_slice(target_epoch.as_bytes());
    out
}

/// Builds the 177-byte AAD for encrypted back-links: `hdr[145] || parent_epoch[32]`.
pub fn back_link_aad(header_bytes: &[u8; HEADER_LEN], parent_epoch: &EpochId) -> [u8; 177] {
    let mut out = [0u8; 177];
    out[..HEADER_LEN].copy_from_slice(header_bytes);
    out[HEADER_LEN..].copy_from_slice(parent_epoch.as_bytes());
    out
}

fn build_member_header(
    vault: VaultId,
    author: DeviceId,
    seq: u64,
    prev: FrameId,
    body_len: usize,
) -> Result<[u8; HEADER_LEN], EpochError> {
    let blen = u32::try_from(body_len).map_err(|_| FrameError::BodyTooLarge {
        len: body_len,
        max: MAX_BODY_LEN,
    })?;
    let hdr = FrameHeader {
        kind: FrameKind::Member,
        vault,
        author,
        seq,
        prev,
        epoch: EpochId::ZERO,
        body_len: blen,
    };
    hdr.validate()?;
    Ok(hdr.encode())
}

#[expect(clippy::too_many_arguments)]
fn build_rotate_attachment(
    vault: VaultId,
    author: DeviceId,
    seq: u64,
    header_bytes: &[u8; HEADER_LEN],
    new_epoch_key: &EpochKey,
    parents: Vec<EpochId>,
    keyring: &EpochKeyring,
    recipients: &BTreeMap<DeviceId, KemPublic>,
) -> Result<Rotate, EpochError> {
    if recipients.is_empty() {
        return Err(EpochError::EmptyRecipients);
    }
    let commit = new_epoch_key.commit(&vault, &author, seq);
    let k_back = new_epoch_key.back_key(&vault, &author, seq);
    let mut back = Vec::new();
    for &parent in &parents {
        if let Some(parent_key) = keyring.get(&parent) {
            let aad = back_link_aad(header_bytes, &parent);
            back.push((parent, seal_back_link(&k_back, &aad, parent_key)?));
        }
    }
    let aad = rotate_wrap_aad(header_bytes);
    let mut wraps = Vec::with_capacity(recipients.len());
    for (&recipient, kem) in recipients {
        let info = wrap_info(&vault, &author, seq, &recipient);
        let wrapped = wrap_epoch_key(SUITE_X25519_WRAP, kem, &info, &aad, new_epoch_key)?;
        wraps.push((recipient, wrapped));
    }
    Ok(Rotate {
        suite: SUITE_X25519_WRAP,
        parents,
        commit,
        back,
        wraps,
    })
}

fn normalize_sorted_unique<T: Ord>(mut items: Vec<T>) -> Vec<T> {
    items.sort();
    items.dedup();
    items
}

/// Builds the genesis `Create` + atomic `Rotate` frame (epoch 0) signed by the recovery root.
pub fn build_create_frame(
    recovery_secret: &RecoverySecret,
    nonce: [u8; 32],
    epoch_key: &EpochKey,
) -> Result<Frame, EpochError> {
    let sign_key = recovery_secret.signing_key();
    let root_id = sign_key.device_id();
    let root_kem = recovery_secret.kem_public();
    let vault = derive_vault_id(&root_id, &nonce);
    let op = MemberOp::Create {
        nonce,
        recovery_kem: root_kem,
    };
    let body_len = member_body_wire_len(0, Some(member_op_wire_len(&op)), Some((0, 0, 1)));
    let header_bytes = build_member_header(vault, root_id, 0, FrameId::ZERO, body_len)?;
    let mut recipients = BTreeMap::new();
    recipients.insert(root_id, root_kem);
    let rotate = build_rotate_attachment(
        vault,
        root_id,
        0,
        &header_bytes,
        epoch_key,
        Vec::new(),
        &EpochKeyring::new(),
        &recipients,
    )?;
    Ok(Frame::sign_member(
        &sign_key,
        vault,
        0,
        FrameId::ZERO,
        MemberBody {
            deps: Vec::new(),
            op: Some(op),
            rotate: Some(rotate),
        },
    )?)
}

/// Builds an `Add` frame (never rotates; optionally carries an inline `Rewrap` per rule E1).
#[expect(clippy::too_many_arguments)]
pub fn build_add_frame(
    author_secret: &DeviceSecret,
    vault: VaultId,
    seq: u64,
    prev: FrameId,
    deps: Vec<FrameId>,
    device: DeviceId,
    device_kem: KemPublic,
    consent: Signature,
    inline_rewrap: Option<(EpochId, &EpochKey)>,
) -> Result<Frame, EpochError> {
    let author = author_secret.device_id();
    let deps = normalize_sorted_unique(deps);
    let op_len = 1
        + 32
        + 32
        + 64
        + 1
        + if inline_rewrap.is_some() {
            rewrap_wire_len(1)
        } else {
            0
        };
    let body_len = member_body_wire_len(deps.len(), Some(op_len), None);
    let header_bytes = build_member_header(vault, author, seq, prev, body_len)?;
    let rewrap = match inline_rewrap {
        None => None,
        Some((epoch, key)) => {
            let info = wrap_info(&vault, &author, seq, &device);
            let aad = rewrap_wrap_aad(&header_bytes, &epoch);
            let wrapped = wrap_epoch_key(SUITE_X25519_WRAP, &device_kem, &info, &aad, key)?;
            Some(Rewrap {
                epoch,
                suite: SUITE_X25519_WRAP,
                wraps: vec![(device, wrapped)],
            })
        }
    };
    Ok(Frame::sign_member(
        author_secret,
        vault,
        seq,
        prev,
        MemberBody {
            deps,
            op: Some(MemberOp::Add {
                device,
                kem: device_kem,
                consent,
                rewrap,
            }),
            rotate: None,
        },
    )?)
}

/// Builds an atomic `Remove` + `Rotate` frame (rule E1).
#[expect(clippy::too_many_arguments)]
pub fn build_remove_frame(
    author_secret: &DeviceSecret,
    vault: VaultId,
    seq: u64,
    prev: FrameId,
    deps: Vec<FrameId>,
    target: DeviceId,
    last_seen_seq: Option<u64>,
    new_epoch_key: &EpochKey,
    parents: Vec<EpochId>,
    keyring: &EpochKeyring,
    recipients: &BTreeMap<DeviceId, KemPublic>,
) -> Result<Frame, EpochError> {
    let author = author_secret.device_id();
    let deps = normalize_sorted_unique(deps);
    let parents = normalize_sorted_unique(parents);
    let back_count = parents.iter().filter(|p| keyring.contains(p)).count();
    let op = MemberOp::Remove {
        device: target,
        last_seen_seq,
    };
    let body_len = member_body_wire_len(
        deps.len(),
        Some(member_op_wire_len(&op)),
        Some((parents.len(), back_count, recipients.len())),
    );
    let header_bytes = build_member_header(vault, author, seq, prev, body_len)?;
    let rotate = build_rotate_attachment(
        vault,
        author,
        seq,
        &header_bytes,
        new_epoch_key,
        parents,
        keyring,
        recipients,
    )?;
    Ok(Frame::sign_member(
        author_secret,
        vault,
        seq,
        prev,
        MemberBody {
            deps,
            op: Some(op),
            rotate: Some(rotate),
        },
    )?)
}

/// Builds an atomic `RotateRecovery` + `Rotate` frame (rule E1).
#[expect(clippy::too_many_arguments)]
pub fn build_rotate_recovery_frame(
    old_root_secret: &DeviceSecret,
    vault: VaultId,
    seq: u64,
    prev: FrameId,
    deps: Vec<FrameId>,
    new_root: DeviceId,
    new_kem: KemPublic,
    consent: Signature,
    new_epoch_key: &EpochKey,
    parents: Vec<EpochId>,
    keyring: &EpochKeyring,
    recipients: &BTreeMap<DeviceId, KemPublic>,
) -> Result<Frame, EpochError> {
    let author = old_root_secret.device_id();
    let deps = normalize_sorted_unique(deps);
    let parents = normalize_sorted_unique(parents);
    let back_count = parents.iter().filter(|p| keyring.contains(p)).count();
    let op = MemberOp::RotateRecovery {
        new: new_root,
        new_kem,
        consent,
    };
    let body_len = member_body_wire_len(
        deps.len(),
        Some(member_op_wire_len(&op)),
        Some((parents.len(), back_count, recipients.len())),
    );
    let header_bytes = build_member_header(vault, author, seq, prev, body_len)?;
    let rotate = build_rotate_attachment(
        vault,
        author,
        seq,
        &header_bytes,
        new_epoch_key,
        parents,
        keyring,
        recipients,
    )?;
    Ok(Frame::sign_member(
        old_root_secret,
        vault,
        seq,
        prev,
        MemberBody {
            deps,
            op: Some(op),
            rotate: Some(rotate),
        },
    )?)
}

/// Builds a standalone `Rotate` frame (`op: None`) for E4 clean-tip convergence or E2 recovery.
#[expect(clippy::too_many_arguments)]
pub fn build_standalone_rotate_frame(
    author_secret: &DeviceSecret,
    vault: VaultId,
    seq: u64,
    prev: FrameId,
    deps: Vec<FrameId>,
    new_epoch_key: &EpochKey,
    parents: Vec<EpochId>,
    keyring: &EpochKeyring,
    recipients: &BTreeMap<DeviceId, KemPublic>,
) -> Result<Frame, EpochError> {
    let author = author_secret.device_id();
    let deps = normalize_sorted_unique(deps);
    let parents = normalize_sorted_unique(parents);
    let back_count = parents.iter().filter(|p| keyring.contains(p)).count();
    let body_len = member_body_wire_len(
        deps.len(),
        None,
        Some((parents.len(), back_count, recipients.len())),
    );
    let header_bytes = build_member_header(vault, author, seq, prev, body_len)?;
    let rotate = build_rotate_attachment(
        vault,
        author,
        seq,
        &header_bytes,
        new_epoch_key,
        parents,
        keyring,
        recipients,
    )?;
    Ok(Frame::sign_member(
        author_secret,
        vault,
        seq,
        prev,
        MemberBody {
            deps,
            op: None,
            rotate: Some(rotate),
        },
    )?)
}

/// Builds a `Rewrap` frame (rule E6 reader duty or Graft 1 recovery repair-wrap).
#[expect(clippy::too_many_arguments)]
pub fn build_rewrap_frame(
    author_secret: &DeviceSecret,
    vault: VaultId,
    seq: u64,
    prev: FrameId,
    deps: Vec<FrameId>,
    target_epoch: EpochId,
    target_key: &EpochKey,
    recipients: &BTreeMap<DeviceId, KemPublic>,
) -> Result<Frame, EpochError> {
    if recipients.is_empty() {
        return Err(EpochError::EmptyRecipients);
    }
    let author = author_secret.device_id();
    let deps = normalize_sorted_unique(deps);
    let op_len = 1 + rewrap_wire_len(recipients.len());
    let body_len = member_body_wire_len(deps.len(), Some(op_len), None);
    let header_bytes = build_member_header(vault, author, seq, prev, body_len)?;
    let aad = rewrap_wrap_aad(&header_bytes, &target_epoch);
    let mut wraps = Vec::with_capacity(recipients.len());
    for (&recipient, kem) in recipients {
        let info = wrap_info(&vault, &author, seq, &recipient);
        let wrapped = wrap_epoch_key(SUITE_X25519_WRAP, kem, &info, &aad, target_key)?;
        wraps.push((recipient, wrapped));
    }
    Ok(Frame::sign_member(
        author_secret,
        vault,
        seq,
        prev,
        MemberBody {
            deps,
            op: Some(MemberOp::Rewrap(Rewrap {
                epoch: target_epoch,
                suite: SUITE_X25519_WRAP,
                wraps,
            })),
            rotate: None,
        },
    )?)
}

/// Graft 1 helper: verifies `target_key` against `graph`'s recorded E2 `commit` for
/// `target_epoch`, then emits a repair `Rewrap` to `recovery_id` (`recovery_kem`).
#[expect(clippy::too_many_arguments)]
pub fn build_recovery_repair_rewrap(
    graph: &EpochGraph,
    author_secret: &DeviceSecret,
    seq: u64,
    prev: FrameId,
    deps: Vec<FrameId>,
    target_epoch: EpochId,
    target_key: &EpochKey,
    recovery_id: DeviceId,
    recovery_kem: KemPublic,
) -> Result<Frame, EpochError> {
    if !graph.verify_epoch_key(target_epoch, target_key) {
        return Err(if graph.get(&target_epoch).is_some() {
            EpochError::CommitMismatch(target_epoch)
        } else {
            EpochError::UnknownEpoch(target_epoch)
        });
    }
    let mut recipients = BTreeMap::new();
    recipients.insert(recovery_id, recovery_kem);
    build_rewrap_frame(
        author_secret,
        graph.vault(),
        seq,
        prev,
        deps,
        target_epoch,
        target_key,
        &recipients,
    )
}
