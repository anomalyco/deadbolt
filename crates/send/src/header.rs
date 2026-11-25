//! The policy header: the cleartext front of every sealed bundle, which the
//! receiver (or a blind store) can read without the key and nobody can change
//! without the key. [`seal`](crate::seal) binds it into chunk 0's AEAD.
//!
//! ```text
//! header = version(1) || flags(1) || expires_unix(8, big-endian)
//! flags  = bit 0: multi_open; every other bit 0
//! ```

use crate::error::{Error, Result};

/// Bytes in an encoded [`PolicyHeader`].
pub const HEADER_LEN: usize = 10;

const VERSION: u8 = 1;
const MULTI_OPEN: u8 = 1;

/// What a sealed bundle says about itself, authenticated by its content key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyHeader {
    /// Unix seconds from which receivers refuse the bundle.
    pub expires_unix: u64,
    /// Whether more than one receiver may open it. Store-backed links always
    /// are: a blind store can't count opens.
    pub multi_open: bool,
}

impl PolicyHeader {
    pub const fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = VERSION;
        out[1] = if self.multi_open { MULTI_OPEN } else { 0 };
        let expires = self.expires_unix.to_be_bytes();
        let mut i = 0;
        while i < 8 {
            out[2 + i] = expires[i];
            i += 1;
        }
        out
    }

    /// Parses exactly [`HEADER_LEN`] bytes, refusing an unknown version or flag.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; HEADER_LEN] = bytes
            .try_into()
            .map_err(|_| Error::Corrupt("bad policy header length".into()))?;
        if bytes[0] != VERSION {
            return Err(Error::Corrupt("unsupported policy header version".into()));
        }
        if bytes[1] & !MULTI_OPEN != 0 {
            return Err(Error::Corrupt("unknown policy header flag".into()));
        }
        let mut expires = [0u8; 8];
        expires.copy_from_slice(&bytes[2..]);
        Ok(Self {
            expires_unix: u64::from_be_bytes(expires),
            multi_open: bytes[1] & MULTI_OPEN != 0,
        })
    }

    /// True once `now` (Unix seconds) reaches the expiry.
    pub const fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_unix
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_refuses_unknown_bits() {
        for header in [
            PolicyHeader {
                expires_unix: 0,
                multi_open: false,
            },
            PolicyHeader {
                expires_unix: 0x0102_0304_0506_0708,
                multi_open: true,
            },
        ] {
            let bytes = header.encode();
            assert_eq!(PolicyHeader::decode(&bytes).unwrap(), header);
        }
        let bytes = PolicyHeader {
            expires_unix: 9,
            multi_open: true,
        }
        .encode();
        assert_eq!(bytes, [1, 1, 0, 0, 0, 0, 0, 0, 0, 9]);
        let mut bad = bytes;
        bad[0] = 2;
        assert!(PolicyHeader::decode(&bad).is_err(), "version");
        let mut bad = bytes;
        bad[1] = 2;
        assert!(PolicyHeader::decode(&bad).is_err(), "flag");
        assert!(PolicyHeader::decode(&bytes[..9]).is_err(), "short");
    }

    #[test]
    fn expiry_is_inclusive() {
        let header = PolicyHeader {
            expires_unix: 100,
            multi_open: false,
        };
        assert!(!header.is_expired(99));
        assert!(header.is_expired(100));
    }
}
