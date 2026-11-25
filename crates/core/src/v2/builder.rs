//! Canonical `Member` frame builders and AAD constructors for `deadbolt_core::v2` epochs.
//!
//! Every builder takes the author's [`ResolvedMembership`] view and refuses a `dep` or `prev`
//! that view could not place, so a frame never cites an unresolved `Remove` it cannot see.
//! A `Rotate` wraps to exactly the view's eligible recipients, and every wrap to the recovery
//! root is the deterministic recovery wrap that any key holder can check.

use std::collections::BTreeMap;

use crate::id::{DeviceId, DeviceSecret, Signature, VaultId};

use super::crypto::{
    EpochId, EpochKey, FrameId, KemPublic, RecoverySecret, SUITE_X25519_WRAP, derive_vault_id,
    seal_back_link, wrap_epoch_key, wrap_info, wrap_recovery_epoch_key,
};
use super::epoch::{EpochError, EpochGraph, EpochKeyring};
use super::frame::{
    Frame, FrameError, FrameHeader, FrameKind, HEADER_LEN, MAX_BODY_LEN, MemberBody, MemberOp,
    Rewrap, Rotate, member_body_wire_len, member_op_wire_len, rewrap_wire_len,
};
use super::membership::ResolvedMembership;

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

/// Sorts and dedups `deps`, refusing any `dep` or non-zero `prev` the view could not place.
fn placed_deps(
    resolved: &ResolvedMembership,
    prev: FrameId,
    deps: Vec<FrameId>,
) -> Result<Vec<FrameId>, EpochError> {
    let deps = normalize_sorted_unique(deps);
    let prev = (!prev.is_zero()).then_some(prev);
    match deps
        .iter()
        .chain(prev.iter())
        .find(|id| !resolved.dag_frames.contains(id))
    {
        Some(&id) => Err(EpochError::UnplacedDep(id)),
        None => Ok(deps),
    }
}

/// The wrap set a `Rotate` in this view must carry: the eligible recipients and their keys,
/// minus `leaving` and plus `joining`.
fn expected_recipients(
    resolved: &ResolvedMembership,
    leaving: Option<DeviceId>,
    joining: Option<(DeviceId, KemPublic)>,
) -> BTreeMap<DeviceId, KemPublic> {
    let mut out: BTreeMap<DeviceId, KemPublic> = resolved
        .eligible_recipients()
        .into_iter()
        .filter_map(|id| Some((id, resolved.kem_of(&id)?)))
        .collect();
    if let Some(id) = leaving {
        out.remove(&id);
    }
    out.extend(joining);
    out
}

/// Wraps `key` to `recipient`: the deterministic recovery wrap when it is `recovery`.
#[expect(clippy::too_many_arguments)]
fn wrap_to(
    vault: &VaultId,
    author: &DeviceId,
    seq: u64,
    recipient: &DeviceId,
    kem: &KemPublic,
    recovery: Option<DeviceId>,
    aad: &[u8],
    key: &EpochKey,
) -> Result<[u8; super::crypto::WRAP_LEN], EpochError> {
    let info = wrap_info(vault, author, seq, recipient);
    Ok(if recovery == Some(*recipient) {
        wrap_recovery_epoch_key(SUITE_X25519_WRAP, kem, &info, aad, key)?
    } else {
        wrap_epoch_key(SUITE_X25519_WRAP, kem, &info, aad, key)?
    })
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
    recovery: Option<DeviceId>,
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
        let wrapped = wrap_to(
            &vault,
            &author,
            seq,
            &recipient,
            kem,
            recovery,
            &aad,
            new_epoch_key,
        )?;
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
        Some(root_id),
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
/// Refuses a device the view has removed (re-adding it would leak post-removal epochs) or
/// that is a recovery root.
#[expect(clippy::too_many_arguments)]
pub fn build_add_frame(
    author_secret: &DeviceSecret,
    vault: VaultId,
    resolved: &ResolvedMembership,
    seq: u64,
    prev: FrameId,
    deps: Vec<FrameId>,
    device: DeviceId,
    device_kem: KemPublic,
    consent: Signature,
    inline_rewrap: Option<(EpochId, &EpochKey)>,
) -> Result<Frame, EpochError> {
    let author = author_secret.device_id();
    let deps = placed_deps(resolved, prev, deps)?;
    if resolved.removed.contains_key(&device) || resolved.recovery_lineage.contains(&device) {
        return Err(EpochError::CannotAdd(device));
    }
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
    resolved: &ResolvedMembership,
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
    let deps = placed_deps(resolved, prev, deps)?;
    if *recipients != expected_recipients(resolved, Some(target), None) {
        return Err(EpochError::RecipientsMismatch);
    }
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
        resolved.active_recovery,
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
    resolved: &ResolvedMembership,
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
    let deps = placed_deps(resolved, prev, deps)?;
    if *recipients != expected_recipients(resolved, Some(author), Some((new_root, new_kem))) {
        return Err(EpochError::RecipientsMismatch);
    }
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
        Some(new_root),
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
    resolved: &ResolvedMembership,
    seq: u64,
    prev: FrameId,
    deps: Vec<FrameId>,
    new_epoch_key: &EpochKey,
    parents: Vec<EpochId>,
    keyring: &EpochKeyring,
    recipients: &BTreeMap<DeviceId, KemPublic>,
) -> Result<Frame, EpochError> {
    let author = author_secret.device_id();
    let deps = placed_deps(resolved, prev, deps)?;
    if *recipients != expected_recipients(resolved, None, None) {
        return Err(EpochError::RecipientsMismatch);
    }
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
        resolved.active_recovery,
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

/// Builds a `Rewrap` frame (rule E6 reader duty or Graft 1 recovery repair-wrap). Every
/// recipient must be eligible in the view, with the view's KEM key.
#[expect(clippy::too_many_arguments)]
pub fn build_rewrap_frame(
    author_secret: &DeviceSecret,
    vault: VaultId,
    resolved: &ResolvedMembership,
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
    let deps = placed_deps(resolved, prev, deps)?;
    let eligible = expected_recipients(resolved, None, None);
    if let Some((&id, _)) = recipients
        .iter()
        .find(|(id, kem)| eligible.get(id) != Some(kem))
    {
        return Err(EpochError::IneligibleRecipient(id));
    }
    let op_len = 1 + rewrap_wire_len(recipients.len());
    let body_len = member_body_wire_len(deps.len(), Some(op_len), None);
    let header_bytes = build_member_header(vault, author, seq, prev, body_len)?;
    let aad = rewrap_wrap_aad(&header_bytes, &target_epoch);
    let mut wraps = Vec::with_capacity(recipients.len());
    for (&recipient, kem) in recipients {
        let wrapped = wrap_to(
            &vault,
            &author,
            seq,
            &recipient,
            kem,
            resolved.active_recovery,
            &aad,
            target_key,
        )?;
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
/// `target_epoch`, then emits a repair `Rewrap` to the view's active recovery root.
#[expect(clippy::too_many_arguments)]
pub fn build_recovery_repair_rewrap(
    graph: &EpochGraph,
    resolved: &ResolvedMembership,
    author_secret: &DeviceSecret,
    seq: u64,
    prev: FrameId,
    deps: Vec<FrameId>,
    target_epoch: EpochId,
    target_key: &EpochKey,
) -> Result<Frame, EpochError> {
    let recovery_id = resolved
        .active_recovery
        .ok_or(EpochError::NoActiveRecovery)?;
    let recovery_kem = resolved
        .kem_of(&recovery_id)
        .ok_or(EpochError::NoActiveRecovery)?;
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
        resolved,
        seq,
        prev,
        deps,
        target_epoch,
        target_key,
        &recipients,
    )
}
