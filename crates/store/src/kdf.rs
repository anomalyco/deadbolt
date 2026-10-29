use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroizing;

use crate::crypto::{self, KEY_LEN, SecretKey};
use crate::error::{Error, Result};

/// Argon2id cost parameters for deriving the local unlock key.
///
/// They are stored (authenticated, not secret) next to the encrypted key set,
/// so they can be raised later without breaking existing stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Lanes. The implementation is single-threaded, so raising this only
    /// changes the output, not the wall-clock cost.
    pub p_cost: u32,
}

impl KdfParams {
    /// 64 MiB, 3 passes, 1 lane: RFC 9106's second recommended profile,
    /// with one lane since the derivation runs single-threaded.
    pub const DEFAULT: Self = Self {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    };

    // Upper bounds on parameters, checked at creation and on every header read,
    // so a tampered header cannot make unlock allocate more than 1 GiB or run for
    // more than about the time of 4 GiB of passes (seconds, not hours). They leave
    // 16x headroom in memory and 21x in work over `DEFAULT`.
    const MAX_M_COST_KIB: u32 = 1024 * 1024;
    const MAX_T_COST: u32 = 64;
    const MAX_P_COST: u32 = 64;
    /// Memory times passes, in KiB.
    const MAX_WORK_KIB: u64 = 4 * 1024 * 1024;

    fn argon2_params(&self) -> Result<Params> {
        if self.m_cost_kib > Self::MAX_M_COST_KIB
            || self.t_cost > Self::MAX_T_COST
            || self.p_cost > Self::MAX_P_COST
            || u64::from(self.m_cost_kib) * u64::from(self.t_cost) > Self::MAX_WORK_KIB
        {
            return Err(Error::InvalidKdfParams(format!(
                "{self:?} exceeds the supported maximum"
            )));
        }
        Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|e| Error::InvalidKdfParams(e.to_string()))
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.argon2_params().map(drop)
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

const ALG_ARGON2ID_V13: u8 = 1;
const SALT_LEN: usize = 16;
pub(crate) const ENCODED_LEN: usize = 1 + 4 + 4 + 4 + SALT_LEN;

/// KDF algorithm, parameters and salt, as stored in the header.
///
/// Encoding (29 bytes): `alg (1) || m_cost_kib (u32 LE) || t_cost (u32 LE) ||
/// p_cost (u32 LE) || salt (16)`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct KdfHeader {
    pub(crate) params: KdfParams,
    salt: [u8; SALT_LEN],
}

impl KdfHeader {
    pub(crate) fn generate(params: KdfParams) -> Result<Self> {
        params.validate()?;
        Ok(Self {
            params,
            salt: crypto::random()?,
        })
    }

    pub(crate) fn encode(&self) -> [u8; ENCODED_LEN] {
        let mut out = [0u8; ENCODED_LEN];
        out[0] = ALG_ARGON2ID_V13;
        out[1..5].copy_from_slice(&self.params.m_cost_kib.to_le_bytes());
        out[5..9].copy_from_slice(&self.params.t_cost.to_le_bytes());
        out[9..13].copy_from_slice(&self.params.p_cost.to_le_bytes());
        out[13..].copy_from_slice(&self.salt);
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; ENCODED_LEN] = bytes
            .try_into()
            .map_err(|_| Error::corrupt("KDF header has the wrong length"))?;
        if bytes[0] != ALG_ARGON2ID_V13 {
            return Err(Error::corrupt(format!(
                "unknown KDF algorithm {}",
                bytes[0]
            )));
        }
        let u32_at =
            |i: usize| u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        let params = KdfParams {
            m_cost_kib: u32_at(1),
            t_cost: u32_at(5),
            p_cost: u32_at(9),
        };
        params
            .validate()
            .map_err(|e| Error::corrupt(format!("stored KDF parameters rejected: {e}")))?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[13..]);
        Ok(Self { params, salt })
    }

    /// Derives the 256-bit local unlock key.
    pub(crate) fn derive(&self, passphrase: &[u8]) -> Result<SecretKey> {
        let params = self.params.argon2_params()?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
        // Allocated here (rather than by argon2) so the working memory, which
        // holds passphrase-derived state, is wiped when dropped. Fallibly, so a
        // machine short of memory gets an error rather than an abort.
        let mut memory = Zeroizing::new(Vec::new());
        memory
            .try_reserve_exact(params.block_count())
            .map_err(|_| {
                Error::InvalidKdfParams(format!("not enough memory for {:?}", self.params))
            })?;
        memory.resize(params.block_count(), Block::new());
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        argon2
            .hash_password_into_with_memory(
                passphrase,
                &self.salt,
                key.as_mut_slice(),
                memory.as_mut_slice(),
            )
            .map_err(|e| Error::InvalidKdfParams(e.to_string()))?;
        Ok(key)
    }
}
