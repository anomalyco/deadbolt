//! Bounded canonical byte writer and reader shared by v2 data, checkpoint and pack payloads.
//!
//! Integers are big-endian, collections carry a `u32` count, and strings are `u32` length
//! plus UTF-8 bytes. Every count is checked against both a limit and the remaining input
//! before anything is allocated.

use crate::id::{DeviceId, ItemId};

use super::crypto::{CryptoError, FrameId};
use super::frame::FrameError;

/// Errors decoding, encoding or opening v2 data-plane payloads.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    #[error("unexpected end of payload")]
    UnexpectedEnd,
    #[error("trailing bytes after payload")]
    TrailingBytes,
    #[error("invalid {what} tag {tag}")]
    InvalidTag { what: &'static str, tag: u8 },
    #[error("non-canonical ordering or duplicate entry in {0}")]
    NotCanonical(&'static str),
    #[error("{what} length {len} exceeds limit {max}")]
    TooLarge {
        what: &'static str,
        len: usize,
        max: usize,
    },
    #[error("invalid UTF-8 in {0}")]
    InvalidUtf8(&'static str),
    #[error("invalid payload: {0}")]
    Invalid(&'static str),
    #[error("frame kind does not match payload")]
    WrongKind,
    #[error("frame error: {0}")]
    Frame(#[from] FrameError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

/// Upper bound on any single collection count in a v2 payload.
pub const MAX_ENTRIES: usize = 1 << 20;

/// Canonical byte writer.
#[derive(Default)]
pub(crate) struct Writer(Vec<u8>);

impl Writer {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub(crate) fn u8(&mut self, v: u8) {
        self.0.push(v);
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn bytes(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }

    pub(crate) fn device(&mut self, v: &DeviceId) {
        self.bytes(v.as_bytes());
    }

    pub(crate) fn frame_id(&mut self, v: &FrameId) {
        self.bytes(v.as_bytes());
    }

    pub(crate) fn item(&mut self, v: &ItemId) {
        self.bytes(v.as_bytes());
    }

    /// Writes a collection count, rejecting counts above `MAX_ENTRIES`.
    pub(crate) fn count(&mut self, len: usize, what: &'static str) -> Result<(), PayloadError> {
        if len > MAX_ENTRIES {
            return Err(PayloadError::TooLarge {
                what,
                len,
                max: MAX_ENTRIES,
            });
        }
        self.u32(u32::try_from(len).map_err(|_| PayloadError::TooLarge {
            what,
            len,
            max: MAX_ENTRIES,
        })?);
        Ok(())
    }

    /// Writes a length-prefixed UTF-8 string no longer than `max` bytes.
    pub(crate) fn str(
        &mut self,
        v: &str,
        max: usize,
        what: &'static str,
    ) -> Result<(), PayloadError> {
        if v.len() > max {
            return Err(PayloadError::TooLarge {
                what,
                len: v.len(),
                max,
            });
        }
        self.u32(u32::try_from(v.len()).map_err(|_| PayloadError::TooLarge {
            what,
            len: v.len(),
            max,
        })?);
        self.bytes(v.as_bytes());
        Ok(())
    }
}

/// Bounded canonical byte reader.
pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], PayloadError> {
        if self.0.len() < n {
            return Err(PayloadError::UnexpectedEnd);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], PayloadError> {
        self.take(N)?
            .try_into()
            .map_err(|_| PayloadError::UnexpectedEnd)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, PayloadError> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32, PayloadError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, PayloadError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    pub(crate) fn device(&mut self) -> Result<DeviceId, PayloadError> {
        Ok(DeviceId::from_bytes(self.array::<32>()?))
    }

    pub(crate) fn frame_id(&mut self) -> Result<FrameId, PayloadError> {
        Ok(FrameId::from_bytes(self.array::<32>()?))
    }

    pub(crate) fn item(&mut self) -> Result<ItemId, PayloadError> {
        Ok(ItemId::from_bytes(self.array::<16>()?))
    }

    /// Reads a collection count whose items each take at least `min_item` bytes.
    pub(crate) fn count(
        &mut self,
        min_item: usize,
        what: &'static str,
    ) -> Result<usize, PayloadError> {
        let len = self.u32()? as usize;
        if len > MAX_ENTRIES {
            return Err(PayloadError::TooLarge {
                what,
                len,
                max: MAX_ENTRIES,
            });
        }
        let need = len
            .checked_mul(min_item)
            .ok_or(PayloadError::UnexpectedEnd)?;
        if self.0.len() < need {
            return Err(PayloadError::UnexpectedEnd);
        }
        Ok(len)
    }

    /// Reads a length-prefixed UTF-8 string no longer than `max` bytes.
    pub(crate) fn str(&mut self, max: usize, what: &'static str) -> Result<String, PayloadError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(PayloadError::TooLarge { what, len, max });
        }
        let raw = self.take(len)?;
        String::from_utf8(raw.to_vec()).map_err(|_| PayloadError::InvalidUtf8(what))
    }

    pub(crate) fn finish(self) -> Result<(), PayloadError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(PayloadError::TrailingBytes)
        }
    }
}

/// Fails with `NotCanonical(what)` unless `prev < next`.
pub(crate) fn ascending<T: Ord>(
    prev: Option<&T>,
    next: &T,
    what: &'static str,
) -> Result<(), PayloadError> {
    match prev {
        Some(p) if next <= p => Err(PayloadError::NotCanonical(what)),
        _ => Ok(()),
    }
}
