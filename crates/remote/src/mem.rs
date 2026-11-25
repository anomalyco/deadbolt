//! [`MemObjStore`]: an honest in-memory [`ObjStore`], the reference the HTTP
//! backends are tested against and the base of [`FaultyObjStore`].
//!
//! [`FaultyObjStore`]: crate::FaultyObjStore

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::error::RemoteError;
use crate::path::{validate_name, validate_prefix};
use crate::store::{ByteRange, ObjStore, PutOutcome};

/// Every object a [`MemObjStore`] held at one moment, for rolling it back.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemSnapshot(BTreeMap<String, Arc<Vec<u8>>>);

impl MemSnapshot {
    /// The names in the snapshot, ascending.
    pub fn names(&self) -> Vec<String> {
        self.0.keys().cloned().collect()
    }
}

/// An in-memory object store. Clones share the same objects.
#[derive(Debug, Clone, Default)]
pub struct MemObjStore {
    objects: Arc<Mutex<BTreeMap<String, Arc<Vec<u8>>>>>,
}

impl MemObjStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn objects(&self) -> MutexGuard<'_, BTreeMap<String, Arc<Vec<u8>>>> {
        self.objects.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every object, for a later [`restore`](Self::restore).
    pub fn snapshot(&self) -> MemSnapshot {
        MemSnapshot(self.objects().clone())
    }

    /// Replaces every object with a snapshot's (a rollback or a restore).
    pub fn restore(&self, snapshot: &MemSnapshot) {
        *self.objects() = snapshot.0.clone();
    }

    /// Drops every object whose name matches.
    pub fn wipe(&self, matches: impl Fn(&str) -> bool) {
        self.objects().retain(|name, _| !matches(name));
    }

    /// Overwrites an object with no checks, as a hostile or buggy store would.
    pub fn plant(&self, name: &str, bytes: &[u8]) {
        self.objects()
            .insert(name.to_owned(), Arc::new(bytes.to_vec()));
    }

    /// An object's bytes, with no checks.
    pub fn peek(&self, name: &str) -> Option<Vec<u8>> {
        self.objects().get(name).map(|b| b.to_vec())
    }

    /// Number of objects.
    pub fn len(&self) -> usize {
        self.objects().len()
    }

    /// True if the store holds nothing.
    pub fn is_empty(&self) -> bool {
        self.objects().is_empty()
    }

    pub(crate) fn put_now(
        &self,
        name: &str,
        bytes: &[u8],
        create_only: bool,
    ) -> Result<PutOutcome, RemoteError> {
        validate_name(name)?;
        let mut objects = self.objects();
        if create_only && objects.contains_key(name) {
            return Ok(PutOutcome::AlreadyExists);
        }
        objects.insert(name.to_owned(), Arc::new(bytes.to_vec()));
        Ok(PutOutcome::Created)
    }

    pub(crate) fn get_now(
        &self,
        name: &str,
        range: Option<ByteRange>,
    ) -> Result<Option<Vec<u8>>, RemoteError> {
        validate_name(name)?;
        Ok(self.objects().get(name).map(|bytes| match range {
            Some(range) => range.slice(bytes).to_vec(),
            None => bytes.to_vec(),
        }))
    }

    pub(crate) fn list_now(
        &self,
        prefix: &str,
        after: Option<&str>,
    ) -> Result<Vec<String>, RemoteError> {
        validate_prefix(prefix)?;
        Ok(list_from(&self.objects(), prefix, after))
    }

    pub(crate) fn delete_now(&self, name: &str) -> Result<(), RemoteError> {
        validate_name(name)?;
        self.objects().remove(name);
        Ok(())
    }
}

pub(crate) fn list_from<V>(
    objects: &BTreeMap<String, V>,
    prefix: &str,
    after: Option<&str>,
) -> Vec<String> {
    let start = match after {
        Some(after) if after >= prefix => after,
        _ => prefix,
    };
    objects
        .range::<str, _>((std::ops::Bound::Included(start), std::ops::Bound::Unbounded))
        .map(|(name, _)| name)
        .skip_while(|name| after.is_some_and(|a| name.as_str() <= a))
        .take_while(|name| name.starts_with(prefix))
        .cloned()
        .collect()
}

impl ObjStore for MemObjStore {
    async fn put(
        &self,
        name: &str,
        bytes: &[u8],
        create_only: bool,
    ) -> Result<PutOutcome, RemoteError> {
        self.put_now(name, bytes, create_only)
    }

    async fn get(
        &self,
        name: &str,
        range: Option<ByteRange>,
    ) -> Result<Option<Vec<u8>>, RemoteError> {
        self.get_now(name, range)
    }

    async fn list(&self, prefix: &str, after: Option<&str>) -> Result<Vec<String>, RemoteError> {
        self.list_now(prefix, after)
    }

    async fn delete(&self, name: &str) -> Result<(), RemoteError> {
        self.delete_now(name)
    }
}
