//! The viewer's outbox: saves and uses the extension can't apply itself,
//! sealed to the app's `D_kem` and left as `outbox/<id hex>.wrap`.
//!
//! ```text
//! entry = "DBOX" || version 1 || suite 1 || wrap 80 || nonce 24 || AEAD(k, nonce, padme(json), aad)
//! wrap  = X25519Wrap(D_kem, info = aad, aad, k)          k: a fresh random key per entry
//! aad   = "deadbolt/v2 outbox\0" || vault 32 || id 16 || entry[..6]
//! ```
//!
//! Every entry gets a fresh random name and is written create-new and synced
//! (W1, W2), so the lock-free extension never races the app's writer. The
//! name's id is in the AAD: a copy under another name doesn't open, so one
//! save can't be replayed as two. Padmé padding hides the password's length.

use deadbolt_core::v2::{
    EpochKey, KemPublic, KemSecret, SUITE_X25519_WRAP, WRAP_LEN, aead_open, aead_seal, padme_pad,
    padme_unpad, unwrap_epoch_key, wrap_epoch_key,
};
use deadbolt_pack::Blocks;
use deadbolt_pack::names::{self, OUTBOX_DIR, OUTBOX_SUFFIX};
use deadbolt_pack::objects::list_outbox;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Result, ViewerError};

const MAGIC: &[u8; 4] = b"DBOX";
const VERSION: u8 = 1;
const AAD_DOMAIN: &[u8] = b"deadbolt/v2 outbox\0";
const PREFIX_LEN: usize = 6;
const NONCE_LEN: usize = 24;
const BODY_OFF: usize = PREFIX_LEN + WRAP_LEN + NONCE_LEN;
/// The largest mutation the viewer queues, as JSON.
pub const MAX_MUTATION_LEN: usize = 64 * 1024;
/// The largest entry the app reads back.
const MAX_ENTRY_LEN: usize = 128 * 1024;

/// Something the extension did that the app applies on its next unlock.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum OutboxMutation {
    /// A login the user chose to save.
    SaveLogin {
        url: String,
        username: String,
        password: Zeroizing<String>,
        #[serde(default)]
        title: Option<String>,
    },
    /// A passkey the extension registered.
    SavePasskey {
        rp_id: String,
        user_name: String,
        /// Base64url.
        user_handle: String,
        /// Base64url.
        credential_id: String,
        /// Base64url PKCS#8.
        private_key: Zeroizing<String>,
        #[serde(default)]
        title: Option<String>,
    },
    /// An item was filled at `used_unix`.
    TouchUsed { item_id: String, used_unix: u64 },
}

impl std::fmt::Debug for OutboxMutation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SaveLogin {
                url,
                username,
                title,
                ..
            } => f
                .debug_struct("SaveLogin")
                .field("url", url)
                .field("username", username)
                .field("title", title)
                .finish_non_exhaustive(),
            Self::SavePasskey {
                rp_id,
                user_name,
                credential_id,
                ..
            } => f
                .debug_struct("SavePasskey")
                .field("rp_id", rp_id)
                .field("user_name", user_name)
                .field("credential_id", credential_id)
                .finish_non_exhaustive(),
            Self::TouchUsed { item_id, used_unix } => f
                .debug_struct("TouchUsed")
                .field("item_id", item_id)
                .field("used_unix", used_unix)
                .finish(),
        }
    }
}

fn aad(vault: &[u8; 32], id: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_DOMAIN.len() + 32 + 16 + PREFIX_LEN);
    out.extend_from_slice(AAD_DOMAIN);
    out.extend_from_slice(vault);
    out.extend_from_slice(id);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&[VERSION, SUITE_X25519_WRAP]);
    out
}

/// Seals `mutation` to `device_kem` and leaves it in the outbox of the
/// vault directory `blocks`. Returns the entry's name.
pub fn queue_save<B: Blocks>(
    blocks: &B,
    vault: &[u8; 32],
    device_kem: &KemPublic,
    mutation: &OutboxMutation,
) -> Result<String> {
    let json = Zeroizing::new(
        serde_json::to_vec(mutation).map_err(|err| ViewerError::invalid(err.to_string()))?,
    );
    if json.len() > MAX_MUTATION_LEN {
        return Err(ViewerError::invalid("mutation too large"));
    }
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(|err| ViewerError::Io {
        message: format!("random number generator: {err}"),
    })?;
    let aad = aad(vault, &id);
    let key = EpochKey::generate()?;
    let wrap = wrap_epoch_key(SUITE_X25519_WRAP, device_kem, &aad, &aad, &key)?;
    let (nonce, sealed) = aead_seal(key.as_bytes(), &aad, &padme_pad(&json)?)?;
    let mut entry = Vec::with_capacity(BODY_OFF + sealed.len());
    entry.extend_from_slice(MAGIC);
    entry.extend_from_slice(&[VERSION, SUITE_X25519_WRAP]);
    entry.extend_from_slice(&wrap);
    entry.extend_from_slice(&nonce);
    entry.extend_from_slice(&sealed);
    let name = names::outbox(&id);
    blocks.create_new(&name, &entry)?;
    Ok(name)
}

/// The id in an entry's name, `outbox/<32 hex>.wrap`.
fn entry_id(name: &str) -> Result<[u8; 16]> {
    let hex = name
        .strip_prefix(OUTBOX_DIR)
        .and_then(|rest| rest.strip_suffix(OUTBOX_SUFFIX))
        .filter(|hex| hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .ok_or_else(|| ViewerError::corrupt("not an outbox entry name"))?;
    crate::item::parse_item_id(hex).map_err(|_| ViewerError::corrupt("not an outbox entry name"))
}

/// Opens one entry's bytes, read from `name`, with the app's `D_kem` secret.
pub fn open_entry(
    vault: &[u8; 32],
    device_kem: &KemSecret,
    name: &str,
    entry: &[u8],
) -> Result<OutboxMutation> {
    let id = entry_id(name)?;
    if entry.len() > MAX_ENTRY_LEN || entry.len() < BODY_OFF {
        return Err(ViewerError::corrupt("outbox entry size"));
    }
    let (prefix, rest) = entry.split_at(PREFIX_LEN);
    if prefix[..4] != *MAGIC || prefix[4] != VERSION {
        return Err(ViewerError::corrupt("not an outbox entry"));
    }
    let suite = prefix[5];
    let (wrap, rest) = rest.split_at(WRAP_LEN);
    let (nonce, sealed) = rest.split_at(NONCE_LEN);
    let wrap: &[u8; WRAP_LEN] = wrap
        .try_into()
        .map_err(|_| ViewerError::corrupt("outbox entry size"))?;
    let nonce: &[u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| ViewerError::corrupt("outbox entry size"))?;
    let aad = aad(vault, &id);
    let key = unwrap_epoch_key(suite, device_kem, &aad, &aad, wrap)?;
    let padded = aead_open(key.as_bytes(), nonce, &aad, sealed)?;
    let json = padme_unpad(&padded)?;
    serde_json::from_slice(json).map_err(|err| ViewerError::corrupt(err.to_string()))
}

/// What [`drain_outbox`] did.
#[derive(Debug, Default)]
pub struct Drained {
    /// Entries applied and deleted.
    pub applied: Vec<String>,
    /// Entries that didn't open, left on disk for the caller to inspect or
    /// delete: an extension can't have written them for this device.
    pub rejected: Vec<(String, ViewerError)>,
}

/// The app's side: opens every entry, oldest name first, hands each to
/// `apply`, and deletes it once `apply` succeeds. An `apply` error stops
/// the drain with that entry (and every later one) still queued.
pub fn drain_outbox<B: Blocks>(
    blocks: &B,
    vault: &[u8; 32],
    device_kem: &KemSecret,
    mut apply: impl FnMut(&str, OutboxMutation) -> Result<()>,
) -> Result<Drained> {
    let mut drained = Drained::default();
    for name in list_outbox(blocks)? {
        let entry = match blocks.read_all(&name) {
            Ok(entry) => entry,
            // Another drain got there first.
            Err(deadbolt_pack::Error::NotFound { .. }) => continue,
            Err(err) => return Err(err.into()),
        };
        match open_entry(vault, device_kem, &name, &entry) {
            Ok(mutation) => {
                apply(&name, mutation)?;
                blocks.delete(&name)?;
                drained.applied.push(name);
            }
            Err(err) => drained.rejected.push((name, err)),
        }
    }
    Ok(drained)
}
