//! Pure domain logic for deadbolt: device and recovery identities, signed v2
//! frames, membership, epochs, typed items and the fold that merges them.
//! No IO, no async; builds for `wasm32-unknown-unknown`.
//!
//! # Model
//!
//! A vault is a set of signed [`v2::Frame`]s in per-author streams: a
//! plaintext membership log (who belongs, which epoch keys exist and who
//! they are wrapped to) and a sealed data log (item edits, the vault name,
//! device cards). A vault is created by its recovery root, whose secret is
//! the 24-word recovery kit ([`recovery`]); the root adds the first device.
//! See [`v2`] for the wire format and rules, and [`Vault`] for how one
//! device holds a vault.
//!
//! # Items
//!
//! Devices edit items with [`DataOp`]s ([`ops`]). `Create` makes an item of
//! a type (an open identifier, see [`schemas`]) with its required fields;
//! `Edit` changes one thing about it. Each field, the name, the tombstone
//! and the rest resolve like registers: an edit replaces what it was based
//! on; among truly concurrent edits the highest frame position wins. Ops
//! that break the item rules in [`item`] are rejected when written.

pub mod autofill;
mod error;
pub mod forms;
#[cfg(feature = "health")]
pub mod health;
mod id;
pub mod item;
pub mod listing;
pub mod ops;
pub mod passkeys;
pub mod password;
pub mod password_rules;
pub mod recovery;
pub mod site;
pub mod site_password;
pub mod tag;
pub mod totp;
pub mod v2;
mod vault;
pub mod webauthn;

pub use error::{DecodeError, Error};
pub use id::{DeviceId, DeviceSecret, Hash, ItemId, Signature, VaultId};
pub use item::{Field, FieldType, ItemError, Schema, SchemaField, schema, schemas};
pub use ops::{Change, DataOp, Source, valid_name};
pub use vault::{
    Author, Deleted, Heads, Item, MAX_FRAME_LEN, MAX_FRAMES, Touch, Vault, VaultWrite,
};

#[cfg(test)]
mod vault_tests;

#[cfg(all(test, feature = "health"))]
mod health_tests;
