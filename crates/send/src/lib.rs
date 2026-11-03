//! Deadbolt Send: hand a sealed bundle (files, secrets, vault items) to someone
//! through a one-time link, live and peer to peer.
//!
//! The sender's daemon serves each share on [`SEND_ALPN`] from an iroh endpoint of
//! its own (a random key per daemon run, not the device key) until it is picked
//! up, expires or is revoked. Nothing is stored anywhere else. The link carries
//! everything the receiver needs, after `#` so it never reaches a server:
//! [`SendTicket`] (the sender's endpoint, an access secret and the content key).
//!
//! The same code runs natively (the daemon, tests) and in the browser
//! (`wasm32-unknown-unknown`, relay only), where `crates/send-web` wraps
//! [`receive`] for the receive page at `deadbolt.pw/r`.
//!
//! ```text
//! receiver -> sender   PROOF  HMAC(secret, "receiver-proof" || 0 || transcript)
//! sender -> receiver   STATUS 0 ok | 1 expired | 2 used | 3 revoked
//!                      then, if ok: len (u64 BE) || sealed bundle
//! receiver -> sender   ACK    1, once every byte arrived
//! ```
//!
//! The transcript binds the proof to this QUIC connection (its TLS exporter) and
//! both endpoint ids, so an observed proof can't be replayed. A proof that matches
//! no share closes the connection with [`close::UNKNOWN`].

mod error;
mod payload;
mod policy;
mod proof;
mod receive;
mod seal;
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
mod server;
mod ticket;

pub use error::{Error, Result};
pub use payload::{Bundle, Entry, Group, Node};
pub use policy::{Policy, Refusal, Share, State};
pub use receive::{Network, Progress, receive, receiver_endpoint};
pub use seal::{CHUNK_LEN, MAX_SEALED_LEN, open, seal};
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub use server::{Clock, Server, ShareInfo, ShareRequest};
pub use ticket::{LINK_BASE, SendTicket, SenderAddr};

/// ALPN of the send protocol.
pub const SEND_ALPN: &[u8] = b"deadbolt/send/1";

/// QUIC application close codes of the send protocol.
pub mod close {
    use iroh::endpoint::VarInt;

    /// The receiver acknowledged the bundle.
    pub const DONE: VarInt = VarInt::from_u32(0);
    /// The proof matched no share this sender serves.
    pub const UNKNOWN: VarInt = VarInt::from_u32(1);
    /// Malformed or timed-out exchange.
    pub const PROTOCOL: VarInt = VarInt::from_u32(2);
}

/// Status byte the sender answers a valid proof with.
pub(crate) mod status {
    pub const OK: u8 = 0;
    pub const EXPIRED: u8 = 1;
    pub const USED: u8 = 2;
    pub const REVOKED: u8 = 3;
}

/// A fresh random 32-byte secret.
pub fn random_secret() -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::fill(out.as_mut()).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(out)
}
