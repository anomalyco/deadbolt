//! Store-backed Send (Fable §2.7): the same sealed bytes live Send serves,
//! left on the vault's remote so a link opens while the sender's machine is
//! off.
//!
//! ```text
//! object = <vault>/s/<name>     name = BLAKE3 derive_key("deadbolt/v2 send name", key)[..16]
//! bytes  = deadbolt_send::seal(key, header { multi_open: true, expires_unix }, payload)
//! link   = presigned GET URL (<= 7 days, never past expiry) + key, after `#`
//! ```
//!
//! A blind store can't count opens or run a PAKE, so these links are
//! **multi-open until expiry** and take no password: whoever holds the link can
//! open it until then. The object carries no signature and no device id, and
//! the name reveals nothing about the key; the store learns the size and the
//! expiry (the header is cleartext, bound into chunk 0's AEAD). Expiry is
//! enforced twice: the presigned URL stops working, and receivers refuse a
//! header past it. [`revoke_send`] deletes the object sooner.

use deadbolt_core::VaultId;
use deadbolt_send::{MAX_SEALED_LEN, PolicyHeader, open, random_secret, seal};
use zeroize::Zeroizing;

use crate::error::RemoteError;
use crate::path::{RemotePath, SEND_NAME_LEN};
use crate::s3::S3Config;
use crate::store::{ByteRange, ObjStore, PutOutcome};

/// The longest a store-backed Send lives: a presigned URL's limit.
pub const MAX_SEND_TTL_SECS: u64 = 604_800;

const NAME_CONTEXT: &str = "deadbolt/v2 send name";

/// What a store-backed Send step failed with.
#[derive(Debug, thiserror::Error)]
pub enum SendStoreError {
    #[error(transparent)]
    Remote(#[from] RemoteError),
    /// Sealing, or opening the object, failed: a wrong key, or bytes or a
    /// header changed.
    #[error(transparent)]
    Seal(#[from] deadbolt_send::Error),
    #[error("a Send expires after now and at most {MAX_SEND_TTL_SECS} s later")]
    BadExpiry,
    #[error("a Send object already exists at {0}")]
    Exists(String),
    #[error("no Send object at {0}: revoked, cleaned up or never uploaded")]
    Missing(String),
    #[error("this link has expired")]
    Expired,
}

/// A Send left on a store: where it is, the key its link carries and its
/// policy. The key is zeroized on drop and never printed.
pub struct StoreSend {
    pub path: RemotePath,
    pub key: Zeroizing<[u8; 32]>,
    pub header: PolicyHeader,
}

impl std::fmt::Debug for StoreSend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreSend")
            .field("path", &self.path.to_name())
            .field("key", &"<redacted>")
            .field("header", &self.header)
            .finish()
    }
}

/// The object name of the Send sealed under `key`.
pub fn send_name(key: &[u8; 32]) -> [u8; SEND_NAME_LEN] {
    let derived = Zeroizing::new(blake3::derive_key(NAME_CONTEXT, key));
    let mut name = [0u8; SEND_NAME_LEN];
    name.copy_from_slice(&derived[..SEND_NAME_LEN]);
    name
}

/// `<vault>/s/<send_name(key)>`.
pub fn send_path(vault: VaultId, key: &[u8; 32]) -> RemotePath {
    RemotePath::Send {
        vault,
        name: send_name(key),
    }
}

/// Seals `payload` (an encoded [`deadbolt_send::Bundle`]) under a fresh key as
/// multi-open until `expires_unix`, and stores it create-only.
pub async fn upload_send(
    store: &impl ObjStore,
    vault: VaultId,
    payload: &[u8],
    now_unix: u64,
    expires_unix: u64,
) -> Result<StoreSend, SendStoreError> {
    if expires_unix <= now_unix || expires_unix - now_unix > MAX_SEND_TTL_SECS {
        return Err(SendStoreError::BadExpiry);
    }
    let key = random_secret()?;
    let header = PolicyHeader {
        expires_unix,
        multi_open: true,
    };
    let sealed = seal(&key, &header, payload)?;
    let path = send_path(vault, &key);
    let name = path.to_name();
    match store.put(&name, &sealed, true).await? {
        PutOutcome::Created => Ok(StoreSend { path, key, header }),
        PutOutcome::AlreadyExists => Err(SendStoreError::Exists(name)),
    }
}

/// A presigned `GET` URL for `send`, valid for `ttl_secs` but never past the
/// Send's expiry. The URL needs no credentials, so it goes in the link.
pub fn presign_send_url(
    config: &S3Config,
    send: &StoreSend,
    now_unix: u64,
    ttl_secs: u32,
) -> Result<String, SendStoreError> {
    if send.header.is_expired(now_unix) {
        return Err(SendStoreError::Expired);
    }
    let left = send.header.expires_unix - now_unix;
    let ttl = u64::from(ttl_secs).min(left).min(MAX_SEND_TTL_SECS);
    // `ttl` is at most `ttl_secs`, so it fits.
    let ttl = u32::try_from(ttl).unwrap_or(ttl_secs);
    Ok(config.presign_get(&send.path.to_name(), now_unix, ttl)?)
}

/// Fetches and opens the Send sealed under `key` in `vault`, refusing it once
/// expired.
pub async fn download_send(
    store: &impl ObjStore,
    vault: VaultId,
    key: &[u8; 32],
    now_unix: u64,
) -> Result<(PolicyHeader, Zeroizing<Vec<u8>>), SendStoreError> {
    let name = send_path(vault, key).to_name();
    // One byte past the cap, so an oversized object is refused, not buffered.
    let range = ByteRange::new(0, MAX_SEALED_LEN as u64);
    let sealed = store
        .get(&name, Some(range))
        .await?
        .ok_or(SendStoreError::Missing(name))?;
    open_stored(key, &sealed, now_unix)
}

/// Opens sealed bytes fetched from a presigned URL, refusing them once their
/// authenticated header has expired.
pub fn open_stored(
    key: &[u8; 32],
    sealed: &[u8],
    now_unix: u64,
) -> Result<(PolicyHeader, Zeroizing<Vec<u8>>), SendStoreError> {
    let (header, payload) = open(key, sealed)?;
    if header.is_expired(now_unix) {
        return Err(SendStoreError::Expired);
    }
    Ok((header, payload))
}

/// Deletes `send`'s object, so its link stops working before it expires.
pub async fn revoke_send(store: &impl ObjStore, send: &StoreSend) -> Result<(), SendStoreError> {
    Ok(store.delete(&send.path.to_name()).await?)
}
