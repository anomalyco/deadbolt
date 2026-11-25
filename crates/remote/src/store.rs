//! The four verbs every remote speaks (Fable §3.3). No compare-and-swap:
//! every name has exactly one legitimate writer or is content-addressed.

use std::future::Future;

use crate::error::RemoteError;

/// What a [`ObjStore::put`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    /// The bytes are stored under the name.
    Created,
    /// `create_only` was set and the name already held an object; nothing
    /// was written. The caller compares the stored bytes with its own.
    AlreadyExists,
}

/// An inclusive byte range, the HTTP `Range: bytes=start-end` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// First byte.
    pub start: u64,
    /// Last byte, inclusive; `None` reads to the end.
    pub end: Option<u64>,
}

impl ByteRange {
    /// `start..=end`.
    pub const fn new(start: u64, end: u64) -> Self {
        Self {
            start,
            end: Some(end),
        }
    }

    /// `start..`.
    pub const fn from(start: u64) -> Self {
        Self { start, end: None }
    }

    /// The `Range` header value.
    pub fn header(&self) -> String {
        match self.end {
            Some(end) => format!("bytes={}-{end}", self.start),
            None => format!("bytes={}-", self.start),
        }
    }

    /// The slice of `bytes` this range selects (empty past the end).
    pub fn slice<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        let len = bytes.len() as u64;
        let start = self.start.min(len);
        let end = self.end.map_or(len, |end| end.saturating_add(1).min(len));
        let (Ok(start), Ok(end)) = (usize::try_from(start), usize::try_from(end)) else {
            return &[];
        };
        bytes.get(start..end.max(start)).unwrap_or(&[])
    }
}

/// A blind object store: `PUT` (optionally create-only), ranged `GET`,
/// sorted `LIST` and idempotent `DELETE`.
///
/// Names and prefixes are checked with [`validate_name`](crate::validate_name)
/// and [`validate_prefix`](crate::validate_prefix) before any request.
pub trait ObjStore {
    /// Stores `bytes` under `name`. With `create_only`, an existing object
    /// is left alone and the call returns [`PutOutcome::AlreadyExists`].
    fn put(
        &self,
        name: &str,
        bytes: &[u8],
        create_only: bool,
    ) -> impl Future<Output = Result<PutOutcome, RemoteError>> + Send;

    /// The object's bytes, or the requested range of them; `None` if absent.
    fn get(
        &self,
        name: &str,
        range: Option<ByteRange>,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, RemoteError>> + Send;

    /// Every name starting with `prefix` and sorting strictly after
    /// `after`, in ascending byte order. Backends follow their own pages;
    /// the caller resumes an interrupted pull by passing the last name it
    /// processed as `after`.
    fn list(
        &self,
        prefix: &str,
        after: Option<&str>,
    ) -> impl Future<Output = Result<Vec<String>, RemoteError>> + Send;

    /// Removes `name`. Deleting a missing object succeeds.
    fn delete(&self, name: &str) -> impl Future<Output = Result<(), RemoteError>> + Send;
}

/// Sorts, deduplicates and filters a backend's raw listing to the trait's
/// contract: names under `prefix`, strictly after `after`, ascending.
#[cfg(feature = "http")]
pub(crate) fn finish_listing(
    mut names: Vec<String>,
    prefix: &str,
    after: Option<&str>,
) -> Vec<String> {
    names.retain(|n| n.starts_with(prefix) && after.is_none_or(|a| n.as_str() > a));
    names.sort_unstable();
    names.dedup();
    names
}
