//! Deadbolt v2 on-disk storage. One directory per vault:
//!
//! ```text
//! <base>/v/<vault>/
//!   members.log         Member frames, append-only, never compacted
//!   gen-<n>.pack        immutable checkpoint pack, byte-identical to the remote p/<pack_hash>
//!   wal-<n>.log         Data and Checkpoint frames written or received after generation n
//!   blob/<hash>         content-addressed attachments
//!   local-<m>.sealed    the device's own state, sealed under DeviceRoot, one file per commit
//!   activity-<k>.log    sealed activity records
//!   outbox/<rand>.wrap  iOS viewer → app
//!   LOCK                the single writer's lock; readers never take it
//! ```
//!
//! The rules, each enforced where it lives:
//!
//! - **W1** create-new, append and delete only, never rename or overwrite
//!   ([`Blocks`]).
//! - **W2** the commit point is the sync of an appended record ([`log::append`]).
//! - **W3** open the newest pack that verifies, then every WAL ([`VaultDir::open`]).
//! - **W4** a torn last record is cut off; a bad record with valid ones after it
//!   is [`Error::CorruptLog`] ([`log::scan`]).
//! - **W5** compaction writes the new generation before deleting the old
//!   ([`VaultDir::compact`]).
//! - **W6** readers take no lock ([`VaultReader`], [`PackReader`]).
//!
//! Local state commits are guarded by a two-phase rollback anchor
//! ([`local`]). The crate builds for `wasm32-unknown-unknown`; only
//! [`FsBlocks`] needs a file system.

pub mod blocks;
mod crypto;
mod error;
pub mod local;
pub mod log;
pub mod names;
pub mod objects;
pub mod pack;
mod vault_dir;

#[cfg(test)]
mod tests;

#[cfg(not(target_arch = "wasm32"))]
pub use blocks::FsBlocks;
pub use blocks::{BlockReader, Blocks, MemBlocks};
pub use crypto::KEY_LEN;
pub use error::{Error, Result};
pub use local::{DeviceRoot, LocalState, MemAnchor, NoopAnchor, RollbackAnchor, RollbackToken};
pub use pack::{PackHeader, PackId, PackInput, PackItem, PackKeys, PackReader, PackSummary};
pub use vault_dir::{Loaded, VaultDir, VaultReader};
