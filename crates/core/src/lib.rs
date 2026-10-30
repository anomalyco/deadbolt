//! Pure domain logic for deadbolt: device identity, signed entries,
//! membership, typed items, item merging and sync helpers. No IO, no async.
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
//! bound to the vault id and the inviting device.
//!
//! The vault name is set by `Create` and changed by `Rename`, a membership op
//! any member may write. Like a field edit, a rename replaces the names it was
//! based on; among truly concurrent renames the highest entry hash wins. Names
//! must satisfy [`valid_name`]; invalid ones are rejected on commit and apply.
//!
//! # Items
//!
//! Data entries carry [`DataOp`]s. `Create` makes an item of a type (an open
//! identifier; v1 knows `login` and `card`, see [`schemas`]) with all its
//! required fields and an optional name; the item id is derived from the
//! entry hash and op index ([`ItemId::of_create`]), so two creates can never
//! claim the same id. `Edit` sets or removes a field, sets or clears the
//! name, or deletes the item. Fields, the name and the tombstone each resolve
//! like registers: an edit replaces what it was based on; among truly
//! concurrent edits the highest entry hash wins and the rest stay in
//! [`Vault::history`]. A field's type travels with its value.
//!
//! Ops that break the item rules in [`item`] are rejected by
//! [`Vault::write`]. [`Vault::apply`] still accepts an entry containing them
//! (rejecting it would strand the author's later entries) but skips each
//! invalid op deterministically, so every device ends up with the same state
//! in any arrival order. Items of types this version does not know are
//! skipped the same way.
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
//! data_op = 0x00 type:str opt_str n:u32 (name:str field)*n   Create (names strictly ascending)
//!         | 0x01 item[16] change                            Edit
//! change  = 0x00 name:str field                             Set
//!         | 0x01 name:str                                   Remove
//!         | 0x02 opt_str                                    Name (absent: clear)
//!         | 0x03                                            Delete
//! field   = field_type:str value:str
//! opt_str = 0x00 | 0x01 str
//! str     = len:u32 utf8[len]
//! ```
//!
//! Item types and field types are strings on the wire so later versions can
//! add types without breaking decoding.
//!
//! The entry hash is `blake3::derive_key("deadbolt 2026-10-15 entry hash v2", body)`
//! (v2: typed items; v1 entries are not readable and there is no migration).
//! An item id is the first 16 bytes of
//! `blake3::derive_key("deadbolt 2026-10-15 item id v1", entry_hash || op_index:u64)`.
//! The signature is Ed25519 (strict verification) over
//! `"deadbolt entry signature v1\0" || hash`. Join consent is the new device's
//! signature over `"deadbolt join consent v2\0" || vault_id || inviter || device`,
//! where the inviter is the `Add`'s author.

pub mod autofill;
mod data;
mod encoding;
mod entry;
mod error;
pub mod forms;
#[cfg(feature = "health")]
pub mod health;
mod id;
pub mod item;
pub mod listing;
mod membership;
pub mod passkeys;
pub mod password;
pub mod password_rules;
pub mod site;
pub mod site_password;
pub mod tag;
pub mod totp;
mod vault;
pub mod webauthn;

pub use data::{Deleted, Item, Version, VersionStatus};
pub use entry::{Change, DataOp, Entry, Log, LogId, MembershipOp, Payload, Source, valid_name};
pub use error::{DecodeError, Error};
pub use id::{DeviceId, DeviceSecret, Hash, ItemId, Signature, VaultId};
pub use item::{Field, FieldType, ItemError, Schema, SchemaField, schema, schemas};
pub use vault::{CREATE_BATCH_BYTES, Heads, MAX_ENTRY_LEN, MAX_MEMBERSHIP_ENTRIES, Vault};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod membership_tests;

#[cfg(test)]
mod tag_tests;

#[cfg(all(test, feature = "health"))]
mod health_tests;
