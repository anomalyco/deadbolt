use deadbolt_core::v2::{EpochKey, KemSecret};
use deadbolt_pack::names::hex;
use deadbolt_pack::{Blocks, PackInput, PackSummary, pack};
use zeroize::Zeroizing;

use crate::{ViewerHit, ViewerKeyBundle, ViewerPasskey, ViewerSecret, pack_item};

mod bundle;
mod deps;
mod outbox;
mod reader;

pub(crate) const VAULT: [u8; 32] = [1; 32];
const AUTHOR: [u8; 32] = [2; 32];
const EPOCH: [u8; 32] = [3; 32];
pub(crate) const NOW: u64 = 1_800_000_000;
pub(crate) const EXPIRES: u64 = NOW + 3600;

pub(crate) fn epoch_key() -> EpochKey {
    EpochKey::from_bytes([4; 32])
}

/// The app's `D_kem`.
pub(crate) fn device_kem() -> KemSecret {
    KemSecret::from_bytes(&[9; 32])
}

pub(crate) fn item_id(i: usize) -> String {
    let mut id = [0xab; 16];
    id[8..].copy_from_slice(&(i as u64).to_be_bytes());
    hex(&id)
}

pub(crate) fn password(i: usize) -> String {
    format!("pw-{i}-{}", "z".repeat(i % 23))
}

/// Item `i` is a login on `site-<i>.com`; every tenth also has a passkey
/// there, every third a TOTP secret.
pub(crate) fn head(i: usize) -> ViewerHit {
    let passkey = i.is_multiple_of(10);
    ViewerHit {
        item_id: item_id(i),
        title: format!("Site {i}"),
        username: Some(format!("user{i}@example.com")),
        urls: vec![format!("https://login.site-{i}.com/signin")],
        passkey_rp_id: passkey.then(|| format!("site-{i}.com")),
        passkey_credential_id: passkey.then(|| format!("cred-{i}")),
        has_password: true,
        has_totp: i.is_multiple_of(3),
    }
}

pub(crate) fn secret(i: usize) -> ViewerSecret {
    ViewerSecret {
        item_id: item_id(i),
        password: Some(Zeroizing::new(password(i))),
        totp: i
            .is_multiple_of(3)
            .then(|| Zeroizing::new("JBSWY3DPEHPK3PXP".to_owned())),
        passkey: i.is_multiple_of(10).then(|| ViewerPasskey {
            credential_id: format!("cred-{i}"),
            user_handle: format!("handle-{i}"),
            private_key: Zeroizing::new(format!("pkcs8-{i}")),
        }),
    }
}

pub(crate) fn input(items: usize, generation: u64) -> PackInput {
    PackInput {
        vault: VAULT,
        author: AUTHOR,
        seq: items as u64,
        epoch: EPOCH,
        generation,
        meta: Zeroizing::new(b"frontier and clocks".to_vec()),
        items: (0..items)
            .map(|i| pack_item(&head(i), &secret(i)).unwrap())
            .collect(),
    }
}

/// Writes `gen-<generation>.pack` with `items` items.
pub(crate) fn write_pack<B: Blocks>(blocks: &B, items: usize, generation: u64) -> PackSummary {
    let name = deadbolt_pack::names::gen_pack(generation);
    pack::write(
        blocks,
        &name,
        &input(items, generation),
        epoch_key().as_bytes(),
    )
    .unwrap()
}

pub(crate) fn bundle_for(summary: &PackSummary) -> ViewerKeyBundle {
    ViewerKeyBundle::derive_for_pack(
        &epoch_key(),
        &summary.header,
        &device_kem().public_key(),
        EXPIRES,
    )
}
