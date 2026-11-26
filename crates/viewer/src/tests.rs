use std::sync::OnceLock;

use deadbolt_core::v2::{DeviceKeys, EpochKey, KemSecret, Pack, RecoverySecret};
use deadbolt_core::{Author, DataOp, Error, Field, FieldType, ItemId, Vault};
use deadbolt_pack::names::hex;
use deadbolt_pack::{Blocks, PackInput, PackSummary, pack};
use zeroize::Zeroizing;

use crate::{ViewerHit, ViewerKeyBundle, ViewerPasskey, ViewerSecret, pack_input};

mod bundle;
mod deps;
mod eligibility;
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

/// The most items any test packs.
const MAX_ITEMS: usize = 5_000;

/// One vault holding item `i` for every `i < MAX_ITEMS`, compacted into
/// a core pack: `(ids, pack)`, ids in creation order.
fn fixture() -> &'static (Vec<ItemId>, Pack) {
    static FIXTURE: OnceLock<(Vec<ItemId>, Pack)> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let author = Author::new(DeviceKeys::from_seed(&[5; 32]), NOW * 1000);
        let (mut vault, _) =
            Vault::create(&RecoverySecret::from_bytes([6; 32]), &author, "viewer", "t").unwrap();
        let ops: Vec<DataOp> = (0..MAX_ITEMS).map(create).collect();
        let (ids, _) = vault
            .transact(|w| w.create_items(&author, ops), |_, _| Ok::<_, Error>(()))
            .unwrap();
        let made = vault
            .transact(
                |w| {
                    w.checkpoint(&author, |pack, site| {
                        let input = crate::pack_input(pack, site, 1).map_err(|e| e.to_string())?;
                        Ok(deadbolt_pack::pack::encode(&input, site.key.as_bytes())
                            .map_err(|e| e.to_string())?
                            .bytes)
                    })
                },
                |_, _| Ok::<_, Error>(()),
            )
            .unwrap();
        (ids, made.pack)
    })
}

/// Item `i` is a login on `site-<i>.com`, or every tenth a passkey there;
/// every third also has a TOTP secret.
fn create(i: usize) -> DataOp {
    let text = |name: &str, value: String| (name.to_owned(), Field::new(FieldType::Text, value));
    let mut fields = vec![text("username", format!("user{i}@example.com"))];
    let kind = if i.is_multiple_of(10) {
        fields.extend([
            text("rp-id", format!("site-{i}.com")),
            text("credential-id", format!("cred-{i}")),
            text("user-handle", format!("handle-{i}")),
            (
                "private-key".into(),
                Field::new(FieldType::Secret, format!("pkcs8-{i}")),
            ),
        ]);
        "passkey"
    } else {
        fields.extend([
            (
                "password".into(),
                Field::new(FieldType::Secret, password(i)),
            ),
            (
                "url".into(),
                Field::new(FieldType::Url, format!("https://login.site-{i}.com/signin")),
            ),
        ]);
        "login"
    };
    if i.is_multiple_of(3) {
        fields.push(("otp".into(), Field::new(FieldType::Otp, "JBSWY3DPEHPK3PXP")));
    }
    DataOp::create(kind, Some(format!("Site {i}")), fields)
}

pub(crate) fn item_id(i: usize) -> String {
    hex(fixture().0[i].as_bytes())
}

/// The fixture's first `items` items as a pack of their own.
pub(crate) fn core_pack(items: usize) -> Pack {
    let (ids, pack) = fixture();
    let mut pack = pack.clone();
    let keep: std::collections::BTreeSet<_> = ids[..items].iter().collect();
    pack.state.items.retain(|id, _| keep.contains(id));
    pack
}

pub(crate) fn password(i: usize) -> String {
    format!("pw-{i}-{}", "z".repeat(i % 23))
}

/// What the viewer shows for item `i`.
pub(crate) fn head(i: usize) -> ViewerHit {
    let passkey = i.is_multiple_of(10);
    ViewerHit {
        item_id: item_id(i),
        title: format!("Site {i}"),
        username: Some(format!("user{i}@example.com")),
        urls: if passkey {
            Vec::new()
        } else {
            vec![format!("https://login.site-{i}.com/signin")]
        },
        passkey_rp_id: passkey.then(|| format!("site-{i}.com")),
        passkey_credential_id: passkey.then(|| format!("cred-{i}")),
        has_password: !passkey,
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
    let site = deadbolt_core::PackSite {
        vault: deadbolt_core::VaultId::from_bytes(VAULT),
        author: deadbolt_core::DeviceId::from_bytes(AUTHOR),
        seq: items as u64,
        epoch: deadbolt_core::v2::EpochId::from_bytes(EPOCH),
        key: epoch_key(),
    };
    pack_input(&core_pack(items), &site, generation).unwrap()
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
