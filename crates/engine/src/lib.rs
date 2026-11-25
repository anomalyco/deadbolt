//! Deadbolt's vault engine: the unlocked state of a device and the rules the
//! daemon answers clients by, with no IO of its own.
//!
//! - [`Engine`] ([`state`]): the device key, its vaults, the address book,
//!   and the one write path, [`Engine::update`], which commits to the
//!   [`VaultStore`] before anything is served.
//! - [`items`]: lookup, listing, writes and trash; [`autofill`] and
//!   [`forms`]: what a web page may list and fill; [`passkeys`]: the
//!   authenticator; [`generate`]: passwords made for a page's field;
//!   [`secrets`]: secret references for commands; [`ssh_keys`]: SSH keys
//!   made, imported and described; [`activity`]: the Activity entries a
//!   request makes, and the [`activity::Ledger`] keeping them in budget;
//!   [`cap`]: the capabilities a caller holds, which a lock wipes.
//!
//! The host owns everything else: the sealed store on disk, the network,
//! the control socket, prompts and timers. Time comes in through a
//! [`Clock`] and storage through a [`VaultStore`], so the engine builds for
//! `wasm32-unknown-unknown` (CI checks it).

pub mod activity;
pub mod autofill;
pub mod cap;
pub mod clock;
pub mod forms;
pub mod generate;
pub mod items;
pub mod passkeys;
pub mod secrets;
pub mod ssh_keys;
pub mod state;
pub mod store;

use data_encoding::HEXLOWER;
use deadbolt_proto::daemon::{DaemonError, ErrorCode};

pub use clock::Clock;
pub use state::{Changes, Engine, Meta, ONLINE_WINDOW_SECS, Peer, PeerId, UnavailableVault};
pub use store::{MemoryStore, VaultStore};

/// An error with the code clients act on (`DaemonError`).
pub fn fail(code: ErrorCode, message: impl Into<String>) -> anyhow::Error {
    DaemonError {
        code,
        message: message.into(),
    }
    .into()
}

/// The code of an error made by [`fail`], if it is one.
pub fn code(error: &anyhow::Error) -> Option<ErrorCode> {
    error.downcast_ref::<DaemonError>().map(|e| e.code)
}

pub fn hex(bytes: &[u8]) -> String {
    HEXLOWER.encode(bytes)
}

pub fn unhex<const N: usize>(text: &str) -> anyhow::Result<[u8; N]> {
    HEXLOWER
        .decode(text.as_bytes())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid id {text}"))
}

#[cfg(test)]
pub(crate) mod testing {
    use std::time::Duration;

    use crate::clock::FixedClock;
    use crate::{Engine, MemoryStore};

    /// 2026-11-18, a fixed now for tests.
    pub const NOW: Duration = Duration::from_secs(1_795_000_000);

    /// A new device in memory, with a default vault `personal`.
    pub fn engine() -> Engine {
        let mut engine = Engine::create(
            Box::new(MemoryStore::new([7; 32])),
            Box::new(FixedClock(NOW)),
            "test",
        )
        .unwrap();
        engine.create_vault("personal").unwrap();
        engine
    }
}
