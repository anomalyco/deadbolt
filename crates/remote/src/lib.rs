//! Deadbolt v2 remote storage, landed dark: nothing in the engine or the CLI
//! uses it yet. A remote is a blind object store with four verbs and no
//! compare-and-swap (Fable §3.3):
//!
//! ```text
//! put(name, bytes, create_only)   PUT, If-None-Match: * when create-only
//! get(name, range?)               GET, Range: bytes=a-b
//! list(prefix, after?)            sorted names
//! delete(name)                    idempotent
//! ```
//!
//! Every name has exactly one legitimate writer (its author's stream) or is
//! content-addressed, so the protocol needs no shared mutable object.
//!
//! - [`path`]: the canonical names (`<vault>/m/<author>/<seq:016x>`, ...).
//! - [`ObjStore`] with [`MemObjStore`], [`FaultyObjStore`] and, behind the
//!   default `http` feature, [`S3ObjStore`] (S3, R2, MinIO) and
//!   [`WebDavObjStore`].
//! - [`sigv4`]: AWS Signature Version 4 and presigned GET URLs, pure.
//! - [`planner`]: push and pull order, the [`SyncAnchor`], and the rollback,
//!   withholding and self-rollback checks.
//!
//! Without the `http` feature the crate builds for `wasm32-unknown-unknown`.

mod error;
mod faulty;
#[cfg(feature = "http")]
mod http;
mod mem;
pub mod path;
pub mod planner;
pub mod s3;
pub mod sigv4;
mod store;
pub mod webdav;
mod xml;

#[cfg(test)]
mod tests;

pub use error::RemoteError;
pub use faulty::{Call, FaultyObjStore};
pub use mem::{MemObjStore, MemSnapshot};
pub use path::{Area, PathError, RemotePath, validate_name, validate_prefix};
pub use planner::{
    Observed, Outbox, OwnTips, PullPlan, PushPlan, PushReport, PushStep, PushStop, RecoveryPlan,
    RemoteAnomaly, RemoteIndex, SelfRollback, StreamKey, SyncAnchor, check_fetched,
    check_regressions, check_self_rollback, check_withholding, plan_pull, plan_push,
    plan_recovery_bootstrap, push,
};
#[cfg(feature = "http")]
pub use s3::S3ObjStore;
pub use s3::{Addressing, S3Config};
pub use store::{ByteRange, ObjStore, PutOutcome};
#[cfg(feature = "http")]
pub use webdav::WebDavObjStore;
pub use webdav::{DavAuth, WebDavConfig};
