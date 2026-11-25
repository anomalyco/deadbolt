//! [`ViewerKeyBundle`]: the pack-scoped keys the foreground app hands the
//! extension through the Keychain (`.biometryCurrentSet`, this device only).
//!
//! ```text
//! bundle = "DBVK" || version 1 || vault 32 || PackId 32 || K_pack 32 || K_ix 32
//!          || D_kem public 32 || expires_unix u64_be                     (173 B)
//! K_pack = KDF("epoch pack",  K_e || vault || EpochId || PackId)
//! K_ix   = KDF("epoch index", K_e || vault || EpochId || PackId)
//! ```
//!
//! It never carries `K_e` or `D_sign`: the extension reads one pack
//! generation and cannot author a frame. `D_kem` is only the public key,
//! which seals outbox entries that only the app can open.

use std::fmt;

use deadbolt_core::VaultId;
use deadbolt_core::v2::{EpochId, EpochKey, KemPublic};
use deadbolt_pack::names::hex;
use deadbolt_pack::{PackHeader, PackKeys};
use zeroize::Zeroizing;

use crate::error::{Result, ViewerError};

const MAGIC: &[u8; 4] = b"DBVK";
const VERSION: u8 = 1;
/// Bytes in an encoded bundle.
pub const BUNDLE_LEN: usize = 4 + 1 + 32 * 5 + 8;

/// Keys that open one pack, and the public key saves are sealed to.
/// `Debug` leaves the two keys out; they are wiped on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct ViewerKeyBundle {
    pub vault: [u8; 32],
    pub pack_id: [u8; 32],
    pub k_pack: Zeroizing<[u8; 32]>,
    pub k_ix: Zeroizing<[u8; 32]>,
    /// The app's `D_kem` public key.
    pub device_kem: [u8; 32],
    /// Unix seconds; the bundle is refused from this second on.
    pub expires_unix: u64,
}

impl ViewerKeyBundle {
    /// The bundle for the pack `header` names, under the epoch key `K_e`
    /// it was sealed with. The foreground app calls this after each repack.
    pub fn derive_for_pack(
        epoch_key: &EpochKey,
        header: &PackHeader,
        device_kem: &KemPublic,
        expires_unix: u64,
    ) -> Self {
        let vault = VaultId::from_bytes(header.vault);
        let epoch = EpochId::from_bytes(header.epoch);
        let pack_id = header.id().0;
        Self {
            vault: header.vault,
            pack_id,
            k_pack: epoch_key.pack_key(&vault, &epoch, &pack_id),
            k_ix: epoch_key.index_key(&vault, &epoch, &pack_id),
            device_kem: *device_kem.as_bytes(),
            expires_unix,
        }
    }

    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_unix
    }

    pub(crate) fn pack_keys(&self) -> PackKeys {
        PackKeys::from_bytes(*self.k_pack, *self.k_ix)
    }

    pub fn device_kem(&self) -> KemPublic {
        KemPublic::from_bytes(self.device_kem)
    }

    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(BUNDLE_LEN));
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        for part in [
            &self.vault,
            &self.pack_id,
            &*self.k_pack,
            &*self.k_ix,
            &self.device_kem,
        ] {
            out.extend_from_slice(part);
        }
        out.extend_from_slice(&self.expires_unix.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != BUNDLE_LEN {
            return Err(ViewerError::InvalidBundle);
        }
        let (head, mut rest) = bytes.split_at(5);
        if head[..4] != *MAGIC || head[4] != VERSION {
            return Err(ViewerError::InvalidBundle);
        }
        let mut take = || -> Result<[u8; 32]> {
            let (part, tail) = rest
                .split_first_chunk::<32>()
                .ok_or(ViewerError::InvalidBundle)?;
            rest = tail;
            Ok(*part)
        };
        let vault = take()?;
        let pack_id = take()?;
        let k_pack = Zeroizing::new(take()?);
        let k_ix = Zeroizing::new(take()?);
        let device_kem = take()?;
        let expires: [u8; 8] = rest.try_into().map_err(|_| ViewerError::InvalidBundle)?;
        Ok(Self {
            vault,
            pack_id,
            k_pack,
            k_ix,
            device_kem,
            expires_unix: u64::from_be_bytes(expires),
        })
    }
}

impl fmt::Debug for ViewerKeyBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ViewerKeyBundle")
            .field("vault", &VaultId::from_bytes(self.vault))
            .field("pack_id", &hex(&self.pack_id))
            .field("device_kem", &self.device_kem())
            .field("expires_unix", &self.expires_unix)
            .finish_non_exhaustive()
    }
}
