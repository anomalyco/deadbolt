//! Deadbolt v2's viewer: what a mobile AutoFill extension runs, inside a
//! memory budget of a few tens of megabytes and with no network.
//!
//! The foreground app (which holds `K_e`, `D_sign` and `D_kem`) repacks
//! the vault into `gen-<n>.pack` and hands the extension a
//! [`ViewerKeyBundle`] through the Keychain: `{vault, PackId, K_pack, K_ix,
//! D_kem public, expiry}`. Those keys open that one pack generation and
//! nothing else, so the extension can never read another generation or
//! author a frame.
//!
//! - [`PackViewer`] opens the pack lock-free (W6), decrypts only the index,
//!   and reads one Head record per hit and one Secret record per fill.
//! - [`queue_save`] seals a save or a use to `D_kem` in
//!   `outbox/<rand>.wrap`; the app's [`drain_outbox`] applies and deletes it.
//! - [`pack_item`] is the app's side of the Head/Secret format.
//!
//! With `ffi` (the default), [`ffi`] is the UniFFI surface for Swift.

#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!();

mod bundle;
mod error;
#[cfg(feature = "ffi")]
pub mod ffi;
mod item;
mod outbox;
mod reader;

#[cfg(test)]
mod tests;

pub use bundle::ViewerKeyBundle;
pub use error::{Result, ViewerError};
pub use item::{ViewerHit, ViewerPasskey, ViewerSecret, item_key, pack_item, rp_key, site_key};
pub use outbox::{Drained, OutboxMutation, drain_outbox, open_entry, queue_save};
pub use reader::PackViewer;
