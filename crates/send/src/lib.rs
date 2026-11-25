//! Deadbolt Send: hand a sealed bundle (files, secrets, vault items) to someone
//! through a link, live and peer to peer or from the vault's remote store.
//!
//! Every share is the same sealed bytes ([`seal`]): a cleartext
//! [`PolicyHeader`] (expiry, multi-open) bound into a chunked XChaCha20-Poly1305
//! stream under a content key that only the link carries. Two ways deliver them:
//!
//! - **Live** (the default `live` feature). The sender's daemon serves each share
//!   on [`SEND_ALPN`] from an iroh endpoint of its own (a random key per daemon
//!   run, not the device key) until it is picked up, expires or is revoked.
//!   The link carries everything the receiver needs, after `#` so it never
//!   reaches a server: [`SendTicket`] (the sender's endpoint, an access secret
//!   and the content key).
//! - **Store-backed.** `deadbolt-remote` leaves the sealed bytes on an S3/R2
//!   remote behind a presigned URL, so the link opens while the sender is off.
//!   That side needs only this crate's sealing, so it builds with
//!   `default-features = false` and pulls in no networking.
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
mod header;
mod payload;
mod policy;
#[cfg(feature = "live")]
mod proof;
#[cfg(feature = "live")]
mod receive;
mod seal;
#[cfg(all(
    feature = "live",
    not(all(target_family = "wasm", target_os = "unknown"))
))]
mod server;
#[cfg(feature = "live")]
mod ticket;

pub use error::{Error, Result};
pub use header::{HEADER_LEN, PolicyHeader};
pub use payload::{Bundle, Entry, Group, Node};
pub use policy::{Policy, Refusal, Share, State};
#[cfg(feature = "live")]
pub use receive::{Network, Progress, receive, receiver_endpoint};
pub use seal::{CHUNK_LEN, MAX_SEALED_LEN, SEAL_OVERHEAD, open, seal};
#[cfg(all(
    feature = "live",
    not(all(target_family = "wasm", target_os = "unknown"))
))]
pub use server::{Clock, Server, ShareInfo, ShareRequest};
#[cfg(feature = "live")]
pub use ticket::{LINK_BASE, SendTicket, SenderAddr};

/// ALPN of the send protocol.
#[cfg(feature = "live")]
pub const SEND_ALPN: &[u8] = b"deadbolt/send/1";

/// QUIC application close codes of the send protocol.
#[cfg(feature = "live")]
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
#[cfg(feature = "live")]
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
