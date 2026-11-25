//! [`FaultyObjStore`]: a [`MemObjStore`] that lies on cue, for the
//! adversarial sync simulations (PR 10 gate: withhold, truncate, stale LIST,
//! duplicate, wipe).

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::error::RemoteError;
use crate::mem::{MemObjStore, MemSnapshot};
use crate::path::validate_prefix;
use crate::store::{ByteRange, ObjStore, PutOutcome};

type Matcher = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// One call the store saw, in order, for asserting push and pull order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    Put {
        name: String,
        create_only: bool,
    },
    Get {
        name: String,
    },
    List {
        prefix: String,
        after: Option<String>,
    },
    Delete {
        name: String,
    },
}

#[derive(Default)]
struct Faults {
    withhold: Vec<Matcher>,
    truncate: Vec<(Matcher, usize)>,
    stale_list: Option<MemSnapshot>,
    lose_put_responses: u32,
    fail_next: u32,
    calls: Vec<Call>,
}

/// A [`MemObjStore`] with programmable faults. Clones share objects and faults.
#[derive(Clone, Default)]
pub struct FaultyObjStore {
    inner: MemObjStore,
    faults: Arc<Mutex<Faults>>,
}

impl std::fmt::Debug for FaultyObjStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FaultyObjStore")
            .field("objects", &self.inner.len())
            .finish_non_exhaustive()
    }
}

impl FaultyObjStore {
    /// An honest, empty store until a fault is set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Wraps an existing store's objects.
    pub fn wrap(inner: MemObjStore) -> Self {
        Self {
            inner,
            faults: Arc::default(),
        }
    }

    /// The honest objects underneath, for planting and peeking.
    pub const fn inner(&self) -> &MemObjStore {
        &self.inner
    }

    fn faults(&self) -> MutexGuard<'_, Faults> {
        self.faults.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hides matching names from `list` and `get` (withholding).
    pub fn withhold(&self, matches: impl Fn(&str) -> bool + Send + Sync + 'static) {
        self.faults().withhold.push(Arc::new(matches));
    }

    /// Serves matching objects cut to their first `keep` bytes.
    pub fn truncate(&self, matches: impl Fn(&str) -> bool + Send + Sync + 'static, keep: usize) {
        self.faults().truncate.push((Arc::new(matches), keep));
    }

    /// Freezes `list` at the current objects while `put` keeps landing
    /// (an eventually consistent or caching LIST).
    pub fn freeze_list(&self) {
        let snapshot = self.inner.snapshot();
        self.faults().stale_list = Some(snapshot);
    }

    /// The next `n` puts land but report a transport error, as when the
    /// response is lost; a retry then sees `AlreadyExists`.
    pub fn lose_put_responses(&self, n: u32) {
        self.faults().lose_put_responses = n;
    }

    /// The next `n` calls fail before touching anything.
    pub fn fail_next(&self, n: u32) {
        self.faults().fail_next = n;
    }

    /// Drops every fault (objects are kept).
    pub fn heal(&self) {
        let calls = std::mem::take(&mut self.faults().calls);
        *self.faults() = Faults {
            calls,
            ..Faults::default()
        };
    }

    /// Every object, for a later [`rollback`](Self::rollback).
    pub fn snapshot(&self) -> MemSnapshot {
        self.inner.snapshot()
    }

    /// Rolls every object back to a snapshot (a restored backup or a
    /// malicious store serving an old cut).
    pub fn rollback(&self, snapshot: &MemSnapshot) {
        self.inner.restore(snapshot);
    }

    /// Deletes matching objects behind the clients' backs.
    pub fn wipe(&self, matches: impl Fn(&str) -> bool) {
        self.inner.wipe(matches);
    }

    /// Every call seen so far.
    pub fn calls(&self) -> Vec<Call> {
        self.faults().calls.clone()
    }

    /// Forgets the call log.
    pub fn clear_calls(&self) {
        self.faults().calls.clear();
    }

    fn enter(&self, call: Call) -> Result<(), RemoteError> {
        let mut faults = self.faults();
        faults.calls.push(call);
        if faults.fail_next > 0 {
            faults.fail_next -= 1;
            return Err(RemoteError::Injected("transient failure"));
        }
        Ok(())
    }

    fn hidden(&self, name: &str) -> bool {
        self.faults().withhold.iter().any(|m| m(name))
    }
}

impl ObjStore for FaultyObjStore {
    async fn put(
        &self,
        name: &str,
        bytes: &[u8],
        create_only: bool,
    ) -> Result<PutOutcome, RemoteError> {
        self.enter(Call::Put {
            name: name.to_owned(),
            create_only,
        })?;
        let outcome = self.inner.put_now(name, bytes, create_only)?;
        let mut faults = self.faults();
        if faults.lose_put_responses > 0 {
            faults.lose_put_responses -= 1;
            return Err(RemoteError::Injected("lost PUT response"));
        }
        Ok(outcome)
    }

    async fn get(
        &self,
        name: &str,
        range: Option<ByteRange>,
    ) -> Result<Option<Vec<u8>>, RemoteError> {
        self.enter(Call::Get {
            name: name.to_owned(),
        })?;
        if self.hidden(name) {
            return Ok(None);
        }
        let Some(mut bytes) = self.inner.get_now(name, range)? else {
            return Ok(None);
        };
        if let Some(keep) = self
            .faults()
            .truncate
            .iter()
            .filter(|(m, _)| m(name))
            .map(|(_, keep)| *keep)
            .min()
        {
            bytes.truncate(keep);
        }
        Ok(Some(bytes))
    }

    async fn list(&self, prefix: &str, after: Option<&str>) -> Result<Vec<String>, RemoteError> {
        self.enter(Call::List {
            prefix: prefix.to_owned(),
            after: after.map(str::to_owned),
        })?;
        validate_prefix(prefix)?;
        let stale = self.faults().stale_list.clone();
        let names = match stale {
            Some(snapshot) => {
                let mut names = snapshot.names();
                names.retain(|n| n.starts_with(prefix) && after.is_none_or(|a| n.as_str() > a));
                names
            }
            None => self.inner.list_now(prefix, after)?,
        };
        Ok(names.into_iter().filter(|n| !self.hidden(n)).collect())
    }

    async fn delete(&self, name: &str) -> Result<(), RemoteError> {
        self.enter(Call::Delete {
            name: name.to_owned(),
        })?;
        self.inner.delete_now(name)
    }
}
