//! Networking for deadbolt: device-to-device sync and pairing over iroh.
//!
//! Peers are identified by their 32-byte Ed25519 public key ([`PeerId`], the iroh
//! endpoint id). Payloads are opaque bytes; the caller supplies membership
//! ([`Membership`]), the sync logic ([`SyncHandler`]) and the pairing logic ([`Joiner`],
//! [`Inviter`]).
//!
//! # Membership gate
//!
//! Every connection on [`SYNC_ALPN`] is checked against [`Membership::is_member`] before
//! it is dialed (endpoint `before_connect` hook) and again once the TLS handshake has
//! authenticated the remote key, on both the accepting and the dialing side (endpoint
//! `after_handshake` hook). A rejected connection is closed before the application reads
//! or writes a single byte. [`Node::enforce_membership`] immediately closes open sync
//! connections to any peer that [`Membership::is_member`] no longer accepts.
//!
//! The caller is responsible for the rest of the membership rules, notably syncing
//! membership with reachable peers on startup before serving data, and ordering
//! membership entries before the data that depends on them.

#[cfg(feature = "application")]
pub mod application;

mod code;
mod error;
mod frame;
mod node;
mod pair;
mod qr;
mod rendezvous;
mod sync;

pub use code::{CODE_WORDS, PairingCode};
pub use error::{Error, HandlerError, Result};
#[cfg(feature = "sim")]
pub use node::Gate as MembershipGate;
pub use node::{DEFAULT_MAX_FRAME_LEN, Node, NodeConfig, PeerAddr, Relays};
pub use pair::{
    DEFAULT_FIND_TIMEOUT, DEFAULT_PAIRING_TTL, Inviter, Joiner, PairingContext, PairingListener,
    PairingOptions, PairingOutcome,
};
#[cfg(feature = "sim")]
pub use pair::{PairingStream, ProvenPairing};
pub use qr::{QrStyle, render_qr};
pub use rendezvous::Rendezvous;
#[cfg(feature = "sim")]
pub use sync::run_sync_session;
pub use sync::{INBOUND_SYNC_TIMEOUT, SyncConnection, SyncHandler, SyncOutcome};

/// ALPN of the sync protocol. Membership-gated.
pub const SYNC_ALPN: &[u8] = b"deadbolt/sync/1";
/// ALPN of the pairing protocol. Only accepted while a pairing code is outstanding.
pub const PAIR_ALPN: &[u8] = b"deadbolt/pair/2";

/// A device's Ed25519 public key, which is also its iroh endpoint id.
pub type PeerId = [u8; 32];

/// An entry as sent or received: opaque bytes that may hold secret values, wiped when
/// dropped.
pub type Blob = zeroize::Zeroizing<Vec<u8>>;

/// The current member set, as seen by this device.
pub trait Membership: Send + Sync {
    fn is_member(&self, id: &[u8; 32]) -> bool;
}

impl<F: Fn(&[u8; 32]) -> bool + Send + Sync> Membership for F {
    fn is_member(&self, id: &[u8; 32]) -> bool {
        self(id)
    }
}

/// Lowercase hex of a peer id.
pub fn fmt_id(id: &PeerId) -> String {
    data_encoding::HEXLOWER.encode(id)
}
