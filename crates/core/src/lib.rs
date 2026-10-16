//! Pure domain logic for deadbolt: device identity, signed entries,
//! membership, item merging and sync helpers. No IO, no async.
//!
//! # Model
//!
//! Every device appends to two signed logs: a membership log and a data log,
//! each with its own `seq` starting at 0. An [`Entry`] references the entries
//! its author had seen (`deps`), including the author's previous entry in the
//! same log. Membership entries only depend on membership entries, so the
//! membership DAG can always be synced first.
//!
//! A device may belong to several vaults with the same device key; vault ids
//! are derived from the creator's key and a random nonce, and join consent is
//! bound to the vault id.
//!
//! The vault name is set by `Create` and changed by `Rename`, a membership op
//! any member may write. Like a field edit, a rename replaces the names it was
//! based on; among truly concurrent renames the highest entry hash wins. Names
//! must satisfy [`valid_name`]; invalid ones are rejected on commit and apply.
//!
//! # Encoding
//!
//! Hand-rolled, length-prefixed and big-endian, with exactly one valid
//! encoding per entry (decoding rejects trailing bytes, unknown tags and
//! unsorted or duplicate deps):
//!
//! ```text
//! entry   = body signature[64]
//! body    = vault[32] author[32] seq:u64 n:u32 dep[32]*n payload   (deps strictly ascending)
//! payload = 0x00 membership | 0x01 n:u32 data_op*n
//! membership = 0x00 device[32] nonce[32] name:str        Create
//!            | 0x01 device[32] consent[64]               Add
//!            | 0x02 device[32] (0x00 | 0x01 seq:u64)     Remove
//!            | 0x03 name:str                             Rename
//! data_op = item[16] (0x00 str str | 0x01 str | 0x02)    Set | DeleteField | DeleteItem
//! str     = len:u32 utf8[len]
//! ```
//!
//! The entry hash is `blake3::derive_key("deadbolt 2026-10-15 entry hash v1", body)`.
//! The signature is Ed25519 (strict verification) over
//! `"deadbolt entry signature v1\0" || hash`. Join consent is a signature over
//! `"deadbolt join consent v1\0" || vault_id`.

mod data;
mod encoding;
mod entry;
mod error;
mod id;
mod membership;
mod vault;

pub use data::{Item, Version, VersionStatus};
pub use entry::{Change, DataOp, Entry, Log, LogId, MembershipOp, Payload, valid_name};
pub use error::{DecodeError, Error};
pub use id::{DeviceId, DeviceSecret, Hash, ItemId, Signature, VaultId};
pub use vault::{Heads, Vault};

#[cfg(test)]
mod tests;
